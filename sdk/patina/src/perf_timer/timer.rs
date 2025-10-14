/// Default PM Timer I/O port.
/// This value was selected based on the QEMU I/O port, since QEMU will most likely be the primary user of the ACPI timer fallback.
pub const DEFAULT_PM_PORT: u16 = 0x608;

#[derive(Debug, Clone, Copy)]
pub enum PmTimer {
    IoPort { port: u16 },
    Mmio { base: u64 },
}

impl Default for PmTimer {
    fn default() -> Self {
        PmTimer::IoPort { port: DEFAULT_PM_PORT }
    }
}

pub trait ArchTimerFunctionality: Send + Sync {
    /// Value of the counter.
    fn cpu_count(&self) -> u64;
    /// Value in Hz of how often the counter increment.
    fn perf_frequency(&self) -> u64;
    /// Value that the performance counter starts with.
    fn cpu_count_start(&self) -> u64 {
        0
    }
    /// Value that the performance counter ends with before it rolls over.
    fn cpu_count_end(&self) -> u64 {
        u64::MAX
    }
}

#[cfg(target_arch = "x86_64")]
pub mod x64 {
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use core::{arch::x86_64, mem};
    use spin::Once;

    use core::arch::x86_64::CpuidResult;

    use crate::perf_timer::timer::{ArchTimerFunctionality, PmTimer};

    const DEFAULT_ACPI_TIMER_FREQUENCY: u64 = 3_579_545; // 3.579545 MHz

    pub struct X64Timer {
        pm_timer_info: PmTimer,
        perf_frequency: Once<u64>, // Frequency should be consistent across a single instance + boot, so calculate once and cache.
    }

    impl ArchTimerFunctionality for X64Timer {
        fn cpu_count(&self) -> u64 {
            unsafe { x86_64::_rdtsc() }
        }

        fn perf_frequency(&self) -> u64 {
            if let Some(cached_freq) = self.perf_frequency.get() {
                return *cached_freq;
            }

            let mut frequency = 0u64;

            // Try to get TSC frequency from CPUID.
            let CpuidResult { eax, ebx, ecx, .. } = unsafe { x86_64::__cpuid(0x15) };
            if eax != 0 && ebx != 0 && ecx != 0 {
                // CPUID 0x15 gives TSC_frequency = (ECX * EAX) / EBX.
                frequency = (ecx as u64 * ebx as u64) / eax as u64;
            } else {
                // CPUID 0x16 gives base frequency in MHz in EAX.
                let CpuidResult { eax, .. } = unsafe { x86_64::__cpuid(0x16) };
                if eax != 0 {
                    frequency = (eax * 1_000_000) as u64;
                }
            }

            if frequency == 0 {
                // If CPUID unavailable (e.g. QEMU), fall back to calibrating TSC frequency using ACPI PM timer.
                frequency = Self::calibrate_tsc_frequency(self.pm_timer_info);
            }

            self.perf_frequency.call_once(|| frequency);
            frequency
        }
    }

    impl X64Timer {
        pub const fn new(pm_timer_info: PmTimer) -> Self {
            Self { pm_timer_info: pm_timer_info, perf_frequency: Once::new() }
        }

        pub fn calibrate_tsc_frequency(pm_timer: PmTimer) -> u64 {
            unsafe {
                // Wait for a PM timer edge to avoid partial intervals
                let mut start_pm = Self::read_pm_timer(pm_timer);
                let mut next_pm;
                loop {
                    next_pm = Self::read_pm_timer(pm_timer);
                    if next_pm != start_pm {
                        break;
                    }
                }
                start_pm = next_pm;

                // Record starting TSC
                let start_tsc = x86_64::_rdtsc();

                // Hz = ticks/second. Divided by 20 ~ ticks / 50 ms
                const TARGET_INTERVAL_SIZE: u64 = 20;
                let target_ticks = (DEFAULT_ACPI_TIMER_FREQUENCY / TARGET_INTERVAL_SIZE) as u32;

                let mut end_pm;
                loop {
                    end_pm = Self::read_pm_timer(pm_timer);
                    let delta = end_pm.wrapping_sub(start_pm);
                    if delta >= target_ticks {
                        break;
                    }
                }

                // Record ending TSC
                let end_tsc = x86_64::_rdtsc();

                // Time elapsed based on PM timer ticks
                let delta_pm = end_pm.wrapping_sub(start_pm) as u64;
                let delta_time_ns = (delta_pm * 1_000_000_000) / DEFAULT_ACPI_TIMER_FREQUENCY;

                // Rdtsc ticks
                let delta_tsc = end_tsc - start_tsc;

                // Frequency = Rdstc ticks / elapsed time
                let freq_hz = (delta_tsc * 1_000_000_000) / delta_time_ns;

                freq_hz
            }
        }

        fn read_pm_timer(pm_timer: PmTimer) -> u32 {
            match pm_timer {
                PmTimer::IoPort { port } => {
                    let value: u32;
                    unsafe {
                        core::arch::asm!(
                            "in eax, dx",
                            in("dx") port,
                            out("eax") value,
                            options(nomem, nostack, preserves_flags),
                        );
                    }
                    value
                }
                PmTimer::Mmio { base } => unsafe { core::ptr::read_volatile(base as *const u32) },
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
pub mod aarch64 {
    use crate::perf_timer::ArchFunctionality;
    use aarch64_cpu::registers::{self, Readable};

    pub struct Aarch64Timer;

    impl ArchTimerFunctionality for Aarch64Timer {
        fn cpu_count(&self) -> u64 {
            registers::CNTPCT_EL0.get()
        }

        fn perf_frequency(&self) -> u64 {
            registers::CNTFRQ_EL0.get()
        }
    }

    impl Aarch64Timer {
        fn new() -> Self {
            Self {}
        }
    }
}

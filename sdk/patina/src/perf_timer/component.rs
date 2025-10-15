use spin::Once;

use alloc::boxed::Box;

use crate as patina;
use crate::{
    component::{IntoComponent, params::*},
    error::EfiError,
    perf_timer::{config::TimerConfig, timer::ArchTimerFunctionality},
};

#[derive(IntoComponent, Default)]
pub struct PerfTimer {}

impl PerfTimer {
    /// Create a new performance timer component.
    pub const fn new() -> Self {
        Self {}
    }

    // sherry: the problem is that we store a specific timer type but fetch trait object
    fn entry_point(&self, config: Config<TimerConfig>) -> core::result::Result<(), EfiError> {
        #[cfg(target_arch = "x86_64")]
        {
            use crate::perf_timer::timer::{ArchTimerFunctionality, x64::X64Timer};
            let timer = X64Timer::new(config.timer_read_info);
            GLOBAL_TIMER.call_once(|| Box::new(timer) as Box<dyn ArchTimerFunctionality>);
        }
        #[cfg(target_arch = "aarch64")]
        {
            use crate::service::aarch64::Aarch64Timer;
            let timer = Aarch64Timer::new();
            GLOBAL_TIMER.call_once(|| Box::new(timer) as Box<dyn ArchTimerFunctionality>);
        }

        Ok(())
    }
}

pub static GLOBAL_TIMER: Once<Box<dyn ArchTimerFunctionality>> = Once::new();

impl PerfTimer {
    pub fn cpu_count() -> u64 {
        GLOBAL_TIMER.get().map_or(0, |t| t.cpu_count())
    }

    pub fn perf_frequency() -> u64 {
        GLOBAL_TIMER.get().map_or(0, |t| t.perf_frequency())
    }

    pub fn cpu_count_start() -> u64 {
        GLOBAL_TIMER.get().map_or(0, |t| t.cpu_count_start())
    }

    pub fn cpu_count_end() -> u64 {
        GLOBAL_TIMER.get().map_or(u64::MAX, |t| t.cpu_count_end())
    }
}

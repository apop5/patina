use crate::perf_timer::timer::PmTimer;

#[derive(Debug, Default)]
pub struct TimerConfig {
    /// The physical address of the RSDP.
    /// Used to read configuration details from primarily the FADT.
    pub timer_read_info: PmTimer,
}

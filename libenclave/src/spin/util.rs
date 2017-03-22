#[inline(always)]
pub fn cpu_relax(count: &mut usize) {
    // This instruction is meant for usage in spinlock loops
    // (see Intel x86 manual, III, 4.2)
    unsafe { asm!("pause" :::: "volatile"); }
    *count += 1;
    if *count >= 1000 {
        ::usercall::yield_now();
        *count = 0;
    }
}

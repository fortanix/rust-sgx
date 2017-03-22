//! A simple heap based on a buddy allocator.  For the theory of buddy
//! allocators, see https://en.wikipedia.org/wiki/Buddy_memory_allocation
//!
//! The basic idea is that our heap size is a power of two, and the heap
//! starts out as one giant free block.  When a memory allocation request
//! is received, we round the requested size up to a power of two, and find
//! the smallest available block we can use.  If the smallest free block is
//! too big (more than twice as big as the memory we want to allocate), we
//! split the smallest free block in half recursively until it's the right
//! size.  This simplifies a lot of bookkeeping, because all our block
//! sizes are a power of 2, which makes it easy to have one free list per
//! block size.

use core::cmp::{max, min};
use core::mem::size_of;
use core::ptr;

use math::PowersOf2;

const MIN_HEAP_ALIGN: usize = 4096;

/// A free block in our heap.  This is actually a header that we store at
/// the start of the block.  We don't store any size information in the
/// header, because we a separate free block list for each block size.
pub struct FreeBlock {
    /// The next block in the free list, or NULL if this is the final
    /// block.
    next: *mut FreeBlock,
}

impl FreeBlock {
    /// Construct a `FreeBlock` header pointing at `next`.
    fn new(next: *mut FreeBlock) -> FreeBlock {
        FreeBlock { next: next }
    }
}

/// The interface to a heap.  This data structure is stored _outside_ the
/// heap somewhere, because every single byte of our heap is potentially
/// available for allocation.
pub struct Heap<'a> {
    /// The base address of our heap.  This must be aligned on a
    /// `MIN_HEAP_ALIGN` boundary.
    heap_base: *mut u8,

    /// The space available in our heap.  This must be a power of 2.
    heap_size: usize,

    /// The free lists for our heap.  The list at `free_lists[0]` contains
    /// the smallest block size we can allocate, and the list at the end
    /// can only contain a single free block the size of our entire heap,
    /// and only when no memory is allocated.
    free_lists: &'a mut [*mut FreeBlock],

    /// Our minimum block size.  This is calculated based on `heap_size`
    /// and the length of the provided `free_lists` array, and it must be
    /// big enough to contain a `FreeBlock` header object.
    min_block_size: usize,

    /// The log base 2 of our block size.  Cached here so we don't have to
    /// recompute it on every allocation (but we haven't benchmarked the
    /// performance gain).
    min_block_size_log2: u8,
}

// A Heap struct is the sole owner of the memory it manages
unsafe impl<'a> Send for Heap<'a> {}

impl<'a> Heap<'a> {
    /// Create a new heap.  `heap_base` must be aligned on a
    /// `MIN_HEAP_ALIGN` boundary, `heap_size` must be a power of 2, and
    /// `heap_size / 2.pow(free_lists.len()-1)` must be greater than or
    /// equal to `size_of::<FreeBlock>()`.  Passing in invalid parameters
    /// may do horrible things.
    pub unsafe fn new(
        heap_base: *mut u8,
        heap_size: usize,
        free_lists: &mut [*mut FreeBlock])
        -> Heap
    {
        // The heap base must not be null.
        assert!(heap_base != ptr::null_mut());

        // We must have at least one free list.
        assert!(free_lists.len() > 0);

        // Calculate our minimum block size based on the number of free
        // lists we have available.
        let min_block_size = heap_size >> (free_lists.len()-1);

        // The heap must be aligned on a 4K bounday.
        assert_eq!(heap_base as usize & (MIN_HEAP_ALIGN-1), 0);

        // The heap must be big enough to contain at least one block.
        assert!(heap_size >= min_block_size);

        // The smallest possible heap block must be big enough to contain
        // the block header.
        assert!(min_block_size >= size_of::<FreeBlock>());

        // The heap size must be a power of 2.  See:
        // http://graphics.stanford.edu/~seander/bithacks.html#DetermineIfPowerOf2
        assert!(heap_size.is_power_of_2());

        // We must have one free list per possible heap block size.
        assert_eq!(min_block_size *
                   (2u32.pow(free_lists.len() as u32 - 1)) as usize,
                   heap_size);

        // Zero out our free list pointers.
        for ptr in free_lists.iter_mut() {
            *ptr = ptr::null_mut();
        }

        // Store all the info about our heap in our struct.
        let mut result = Heap {
            heap_base: heap_base,
            heap_size: heap_size,
            free_lists: free_lists,
            min_block_size: min_block_size,
            min_block_size_log2: min_block_size.log2(),
        };

        // Insert the entire heap onto the appropriate free list as a
        // single block.
        let order = result.allocation_order(heap_size, 1)
            .expect("Failed to calculate order for root heap block");
        result.free_list_insert(order, heap_base);
        
        // Return our newly-created heap.
        result
    }

    /// Figure out what size block we'll need to fulfill an allocation
    /// request.  This is deterministic, and it does not depend on what
    /// we've already allocated.  In particular, it's important to be able
    /// to calculate the same `allocation_size` when freeing memory as we
    /// did when allocating it, or everything will break horribly.
    pub fn allocation_size(&self, mut size: usize, align: usize) -> Option<usize> {
        // Sorry, we don't support weird alignments.
        if !align.is_power_of_2() { return None; }

        // We can't align any more precisely than our heap base alignment
        // without getting much too clever, so don't bother.
        if align > MIN_HEAP_ALIGN { return None; }

        // We're automatically aligned to `size` because of how our heap is
        // sub-divided, but if we need a larger alignment, we can only do
        // it be allocating more memory.
        if align > size { size = align; }

        // We can't allocate blocks smaller than `min_block_size`.
        size = max(size, self.min_block_size);

        // Round up to the next power of two.
        size = size.next_power_of_2();

        // We can't allocate a block bigger than our heap.
        if size > self.heap_size { return None; }

        Some(size)
    }

    /// The "order" of an allocation is how many times we need to double
    /// `min_block_size` in order to get a large enough block, as well as
    /// the index we use into `free_lists`.
    pub fn allocation_order(&self, size: usize, align: usize) -> Option<usize> {
        self.allocation_size(size, align).map(|s| {
            (s.log2() - self.min_block_size_log2) as usize
        })
    }

    /// The size of the blocks we allocate for a given order.
    fn order_size(&self, order: usize) -> usize {
        1 << (self.min_block_size_log2 as usize + order)
    }

    /// Pop a block off the appropriate free list.
    unsafe fn free_list_pop(&mut self, order: usize) -> Option<*mut u8> {
        let candidate = self.free_lists[order];
        if candidate != ptr::null_mut() {
            self.free_lists[order] = (*candidate).next;
            Some(candidate as *mut u8)
        } else {
            None
        }
    }

    /// Insert `block` of order `order` onto the appropriate free list.
    unsafe fn free_list_insert(&mut self, order: usize, block: *mut u8) {
        let free_block_ptr = block as *mut FreeBlock;
        *free_block_ptr = FreeBlock::new(self.free_lists[order]);
        self.free_lists[order] = free_block_ptr;
    }

    /// Attempt to remove a block from our free list, returning true
    /// success, and false if the block wasn't on our free list.  This is
    /// the slowest part of a primitive buddy allocator, because it runs in
    /// O(log N) time where N is the number of blocks of a given size.
    ///
    /// We could perhaps improve this by keeping our free lists sorted,
    /// because then "nursery generation" allocations would probably tend
    /// to occur at lower addresses and then be faster to find / rule out
    /// finding.
    unsafe fn free_list_remove(
        &mut self, order: usize, block: *mut u8)
        -> bool
    {
        let block_ptr = block as *mut FreeBlock;

        // Yuck, list traversals are gross without recursion.  Here,
        // `*checking` is the pointer we want to check, and `checking` is
        // the memory location we found it at, which we'll need if we want
        // to replace the value `*checking` with a new value.
        let mut checking: *mut *mut FreeBlock = &mut self.free_lists[order];

        // Loop until we run out of free blocks.
        while *checking != ptr::null_mut() {
            // Is this the pointer we want to remove from the free list?
            if *checking == block_ptr {
                // Yup, this is the one, so overwrite the value we used to
                // get here with the next one in the sequence.
                *checking = (*(*checking)).next;
                return true;
            }

            // Haven't found it yet, so point `checking` at the address
            // containing our `next` field.  (Once again, this is so we'll
            // be able to reach back and overwrite it later if necessary.)
            checking = &mut ((*(*checking)).next);
        }
        false
    }

    /// Split a `block` of order `order` down into a block of order
    /// `order_needed`, placing any unused chunks on the free list.
    unsafe fn split_free_block(
        &mut self, block: *mut u8, mut order: usize, order_needed: usize)
    {
        // Get the size of our starting block.
        let mut size_to_split = self.order_size(order);

        // Progressively cut our block down to size.
        while order > order_needed {
            // Update our loop counters to describe a block half the size.
            size_to_split >>= 1;
            order -= 1;

            // Insert the "upper half" of the block into the free list.
            let split = block.offset(size_to_split as isize);
            self.free_list_insert(order, split);
        }
    }

    /// Allocate a block of memory large enough to contain `size` bytes,
    /// and aligned on `align`.  This will return NULL if the `align` is
    /// greater than `MIN_HEAP_ALIGN`, if `align` is not a power of 2, or
    /// if we can't find enough memory.
    ///
    /// All allocated memory must be passed to `deallocate` with the same
    /// `size` and `align` parameter, or else horrible things will happen.
    pub unsafe fn allocate(&mut self, size: usize, align: usize) -> *mut u8
    {
        // Figure out which order block we need.
        if let Some(order_needed) = self.allocation_order(size, align) {

            // Start with the smallest acceptable block size, and search
            // upwards until we reach blocks the size of the entire heap.
            for order in order_needed..self.free_lists.len() {

                // Do we have a block of this size?
                if let Some(block) = self.free_list_pop(order) {

                    // If the block is too big, break it up.  This leaves
                    // the address unchanged, because we always allocate at
                    // the head of a block.
                    if order > order_needed {
                        self.split_free_block(block, order, order_needed);
                    }

                    // We have an allocation, so quit now.
                    return block;
                }
            }

            // We couldn't find a large enough block for this allocation.
            ptr::null_mut()
        } else {
            // We can't allocate a block with the specified size and
            // alignment.
            ptr::null_mut()
        }
    }

    /// Given a `block` with the specified `order`, find the "buddy" block,
    /// that is, the other half of the block we originally split it from,
    /// and also the block we could potentially merge it with.
    pub unsafe fn buddy(&self, order: usize, block: *mut u8) -> Option<*mut u8> {
        let relative = (block as usize) - (self.heap_base as usize);
        let size = self.order_size(order);
        if size >= self.heap_size {
            // The main heap itself does not have a budy.
            None
        } else {
            // Fun: We can find our buddy by xoring the right bit in our
            // offset from the base of the heap.
            Some(self.heap_base.offset((relative ^ size) as isize))
        }
    }

    /// Deallocate a block allocated using `allocate`.  Note that the
    /// `old_size` and `align` values must match the values passed to
    /// `allocate`, or our heap will be corrupted.
    pub unsafe fn deallocate(
        &mut self, ptr: *mut u8, old_size: usize, align: usize)
    {
        let initial_order = self.allocation_order(old_size, align)
            .expect("Tried to dispose of invalid block");

        // The fun part: When deallocating a block, we also want to check
        // to see if its "buddy" is on the free list.  If the buddy block
        // is also free, we merge them and continue walking up.
        //
        // `block` is the biggest merged block we have so far.
        let mut block = ptr;
        for order in initial_order..self.free_lists.len() {
            // Would this block have a buddy?
            if let Some(buddy) = self.buddy(order, block) {
                // Is this block's buddy free?
                if self.free_list_remove(order, buddy) {
                    // Merge them!  The lower address of the two is the
                    // newly-merged block.  Then we want to try again.
                    block = min(block, buddy);
                    continue;
                }
            }

            // If we reach here, we didn't find a buddy block of this size,
            // so take what we've got and mark it as free.
            self.free_list_insert(order, block);
            return;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use core::ptr;

    extern "C" {
        /// We need this to allocate aligned memory for our heap.
        fn memalign(alignment: usize, size: usize) -> *mut u8;

        // Release our memory.
        fn free(ptr: *mut u8);
    }

    #[test]
    fn test_allocation_size_and_order() {
        unsafe {
            let heap_size = 256;
            let mem = memalign(4096, heap_size);
            let mut free_lists: [*mut FreeBlock; 5] = [0 as *mut _; 5];
            let heap = Heap::new(mem, heap_size, &mut free_lists);

            // TEST NEEDED: Can't align beyond MIN_HEAP_ALIGN.

            // Can't align beyond heap_size.
            assert_eq!(None, heap.allocation_size(256, 256*2));

            // Simple allocations just round up to next block size.
            assert_eq!(Some(16), heap.allocation_size(0, 1));
            assert_eq!(Some(16), heap.allocation_size(1, 1));
            assert_eq!(Some(16), heap.allocation_size(16, 1));
            assert_eq!(Some(32), heap.allocation_size(17, 1));
            assert_eq!(Some(32), heap.allocation_size(32, 32));
            assert_eq!(Some(256), heap.allocation_size(256, 256));

            // Aligned allocations use alignment as block size.
            assert_eq!(Some(64), heap.allocation_size(16, 64));

            // Block orders.
            assert_eq!(Some(0), heap.allocation_order(0, 1));
            assert_eq!(Some(0), heap.allocation_order(1, 1));
            assert_eq!(Some(0), heap.allocation_order(16, 16));
            assert_eq!(Some(1), heap.allocation_order(32, 32));
            assert_eq!(Some(2), heap.allocation_order(64, 64));
            assert_eq!(Some(3), heap.allocation_order(128, 128));
            assert_eq!(Some(4), heap.allocation_order(256, 256));
            assert_eq!(None, heap.allocation_order(512, 512));

            free(mem);
        }
    }

    #[test]
    fn test_buddy() {
        unsafe {
            let heap_size = 256;
            let mem = memalign(4096, heap_size);
            let mut free_lists: [*mut FreeBlock; 5] = [0 as *mut _; 5];
            let heap = Heap::new(mem, heap_size, &mut free_lists);

            let block_16_0 = mem;
            let block_16_1 = mem.offset(16);
            assert_eq!(Some(block_16_1), heap.buddy(0, block_16_0));
            assert_eq!(Some(block_16_0), heap.buddy(0, block_16_1));

            let block_32_0 = mem;
            let block_32_1 = mem.offset(32);
            assert_eq!(Some(block_32_1), heap.buddy(1, block_32_0));
            assert_eq!(Some(block_32_0), heap.buddy(1, block_32_1));

            let block_32_2 = mem.offset(64);
            let block_32_3 = mem.offset(96);
            assert_eq!(Some(block_32_3), heap.buddy(1, block_32_2));
            assert_eq!(Some(block_32_2), heap.buddy(1, block_32_3));

            let block_256_0 = mem;
            assert_eq!(None, heap.buddy(4, block_256_0));

            free(mem);
        }
    }

    #[test]
    fn test_alloc_and_dealloc() {
        unsafe {
            let heap_size = 256;
            let mem = memalign(4096, heap_size);
            let mut free_lists: [*mut FreeBlock; 5] = [0 as *mut _; 5];
            let mut heap = Heap::new(mem, heap_size, &mut free_lists);

            let block_16_0 = heap.allocate(8, 8);
            assert_eq!(mem, block_16_0);

            let bigger_than_heap = heap.allocate(4096, heap_size);
            assert_eq!(ptr::null_mut(), bigger_than_heap);

            let bigger_than_free = heap.allocate(heap_size, heap_size);
            assert_eq!(ptr::null_mut(), bigger_than_free);

            let block_16_1 = heap.allocate(8, 8);
            assert_eq!(mem.offset(16), block_16_1);

            let block_16_2 = heap.allocate(8, 8);
            assert_eq!(mem.offset(32), block_16_2);

            let block_32_2 = heap.allocate(32, 32);
            assert_eq!(mem.offset(64), block_32_2);

            let block_16_3 = heap.allocate(8, 8);
            assert_eq!(mem.offset(48), block_16_3);

            let block_128_1 = heap.allocate(128, 128);
            assert_eq!(mem.offset(128), block_128_1);

            let too_fragmented = heap.allocate(64, 64);
            assert_eq!(ptr::null_mut(), too_fragmented);

            heap.deallocate(block_32_2, 32, 32);
            heap.deallocate(block_16_0, 8, 8);
            heap.deallocate(block_16_3, 8, 8);
            heap.deallocate(block_16_1, 8, 8);
            heap.deallocate(block_16_2, 8, 8);

            let block_128_0 = heap.allocate(128, 128);
            assert_eq!(mem.offset(0), block_128_0);

            heap.deallocate(block_128_1, 128, 128);
            heap.deallocate(block_128_0, 128, 128);

            // And allocate the whole heap, just to make sure everything
            // got cleaned up correctly.
            let block_256_0 = heap.allocate(256, 256);
            assert_eq!(mem.offset(0), block_256_0);

            free(mem);
        }
    }
}        

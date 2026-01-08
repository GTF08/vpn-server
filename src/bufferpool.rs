use bytes::BytesMut;
use std::sync::{Arc, Mutex};

pub struct BytesPool {
    buffers: Mutex<Vec<BytesMut>>,    // Защищённый Mutex
    free_list: Mutex<Vec<usize>>,     // Отдельный Mutex
}

impl BytesPool {
    pub fn new(count: usize, buffer_size: usize) -> Self {
        let buffers = (0..count)
            .map(|_| BytesMut::with_capacity(buffer_size))
            .collect();
        
        let buffers = Mutex::new(buffers);
        let free_list = Mutex::new((0..count).collect());
        
        Self { buffers, free_list}
    }
    
    pub fn acquire(self: &Arc<Self>) -> Option<BufferHandle> {
        // 1. Берём свободный индекс
        let idx = {
            let mut free = self.free_list.lock().unwrap();
            free.pop()?
        };
        
        // 2. Забираем буфер
        let buf = {
            let mut buffers = self.buffers.lock().unwrap();
            std::mem::take(&mut buffers[idx])
        };
        
        Some(BufferHandle::new(Arc::clone(self), idx, buf))
    }
    
    fn release(&self, idx: usize, mut buf: BytesMut) {
        // Очищаем буфер
        buf.clear();
        
        // Возвращаем в пул
        {
            let mut buffers = self.buffers.lock().unwrap();
            buffers[idx] = buf;
        }
        
        // Помечаем как свободный
        {
            let mut free = self.free_list.lock().unwrap();
            free.push(idx);
        }
    }
}

// RAII Handle

// pub trait ExpandBuffer: AsRef<[u8]> + AsMut<[u8]> {
//     fn buf_capacity(&self) -> usize;
//     fn buf_resize(&mut self, new_len: usize, value: u8);
//     fn buf_extend_from_slice(&mut self, src: &[u8]);
// }


pub struct BufferHandle {
    pool: Arc<BytesPool>,
    idx: usize,
    buf: BytesMut,
}

impl BufferHandle {
    pub fn new(pool: Arc<BytesPool>, idx: usize, buf: BytesMut) -> Self {
        Self { pool, idx, buf }
    }

    pub fn data(&self) -> &BytesMut {
        &self.buf
    }
    
    pub fn data_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    pub unsafe fn set_len(&mut self, len: usize) {
        unsafe {
            self.buf.set_len(len);
        }
    }
}

// impl Index<usize> for BufferHandle {
//     type Output = u8; // The type returned by the index operation

//     fn index(&self, index: usize) -> &Self::Output {
//         &self.data()[index] // Delegate to the underlying Vec's index implementation
//     }
// }

// impl IndexMut<usize> for BufferHandle {
//     // The method to get a mutable reference to the element
//     fn index_mut(&mut self, index: usize) -> &mut Self::Output {
//         &mut self.data_mut()[index] // Delegate to Vec's index_mut implementation
//     }
// }

// impl Index<Range<usize>> for BufferHandle {
//     type Output = [u8]; // The type returned by the index operation

//     fn index(&self, index: Range<usize>) -> &Self::Output {
//         &self.data()[index] // Delegate to the underlying Vec's index implementation
//     }
// }

// impl IndexMut<Range<usize>> for BufferHandle {
//     // The method to get a mutable reference to the element
//     fn index_mut(&mut self, index: Range<usize>) -> &mut Self::Output {
//         &mut self.data_mut()[index] // Delegate to Vec's index_mut implementation
//     }
// }

// impl Index<RangeFrom<usize>> for BufferHandle {
//     type Output = [u8]; // The type returned by the index operation

//     fn index(&self, index: RangeFrom<usize>) -> &Self::Output {
//         &self.data()[index] // Delegate to the underlying Vec's index implementation
//     }
// }

// impl IndexMut<RangeFrom<usize>> for BufferHandle {
//     // The method to get a mutable reference to the element
//     fn index_mut(&mut self, index: RangeFrom<usize>) -> &mut Self::Output {
//         &mut self.data_mut()[index] // Delegate to Vec's index_mut implementation
//     }
// }

// impl Index<RangeTo<usize>> for BufferHandle {
//     type Output = [u8]; // The type returned by the index operation

//     fn index(&self, index: RangeTo<usize>) -> &Self::Output {
//         &self.data()[index] // Delegate to the underlying Vec's index implementation
//     }
// }

// impl IndexMut<RangeTo<usize>> for BufferHandle {
//     // The method to get a mutable reference to the element
//     fn index_mut(&mut self, index: RangeTo<usize>) -> &mut Self::Output {
//         &mut self.data_mut()[index] // Delegate to Vec's index_mut implementation
//     }
// }


// // Реализуем AsMut<[u8]> для BufferHandle
// impl std::convert::AsMut<[u8]> for BufferHandle {
//     fn as_mut(&mut self) -> &mut [u8] {
//         self.buf.as_mut()
//     }
// }

// // Реализуем AsRef<[u8]> для BufferHandle
// impl std::convert::AsRef<[u8]> for BufferHandle {
//     fn as_ref(&self) -> &[u8] {
//         self.buf.as_ref()
//     }
// }

impl Drop for BufferHandle {
    fn drop(&mut self) {
        let buf = std::mem::take(&mut self.buf);
        self.pool.release(self.idx, buf);
    }
}
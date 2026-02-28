use bytes::BytesMut;
use std::sync::{Arc};
use crossbeam_queue::ArrayQueue;

#[derive(Clone)]
pub struct BytesPool {
    buffers: Arc<ArrayQueue<BytesMut>>
}

impl BytesPool {
    pub fn new(count: usize, buffer_size: usize) -> Self {
        let buffers = ArrayQueue::new(count);
        for i in 0..count {
            buffers.push(BytesMut::with_capacity(buffer_size)).unwrap();
        }
        let buffers = Arc::new(buffers);
        
        Self { buffers}
    }
    
    pub fn acquire(&self) -> Option<BufferHandle> {
        // 1. Берём свободный индекс
        // let idx = {
        //     let mut free = self.free_list.lock().await;
        //     free.pop()?
        // };
        
        // // 2. Забираем буфер
        // let buf = {
        //     let mut buffers = self.buffers.lock().await;
        //     std::mem::take(&mut buffers[idx])
        // };
        
        // Some(BufferHandle::new(Arc::clone(self), idx, buf))
        let buf = self.buffers.pop()?;
        Some(BufferHandle::new(self.buffers.clone(), buf))
    }
    
    fn release(&self, mut buf: BytesMut) {
        // Очищаем буфер
        buf.clear();
        
        self.buffers.push(buf).unwrap();
    }
}


pub struct BufferHandle {
    queue: Arc<ArrayQueue<BytesMut>>,
    buf: BytesMut,
}

impl BufferHandle {
    fn new(queue: Arc<ArrayQueue<BytesMut>>, buf: BytesMut) -> Self {
        Self { queue, buf }
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

impl Drop for BufferHandle {
    fn drop(&mut self) {
        let buf = std::mem::take(&mut self.buf);
        self.queue.push(buf).unwrap();
    }
}
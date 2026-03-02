use bytes::BytesMut;
use libc::{sockaddr_storage, socklen_t};
use rayon::iter::IntoParallelIterator;
use tun_rs::ExpandBuffer;
use std::{net::SocketAddr, sync::Arc};
use crossbeam_queue::ArrayQueue;


type Item = (Vec<(sockaddr_storage, socklen_t)>, Vec<BytesMut>);

#[derive(Clone)]
pub struct BatchBufferPool {
    buffers: Arc<ArrayQueue<Item>>
}

impl BatchBufferPool {
    pub fn new(count: usize, batch_size: usize, buffer_size: usize) -> Self {
        let buffers = ArrayQueue::new(count);
        for _i in 0..count {
            let batch_bufs: Vec<BytesMut> = 
                std::iter::repeat_with(|| BytesMut::with_capacity(buffer_size))
                .take(batch_size)
                .collect();
            let mut batch = (
                vec![unsafe {std::mem::zeroed()}; batch_size], 
                batch_bufs
            );
            batch.0.iter_mut().for_each(|(_, addrlen)| {
                *addrlen = std::mem::size_of::<sockaddr_storage>() as socklen_t;
            });
            //let batch = vec![(None, BytesMut::with_capacity(buffer_size)); batch_size];
            buffers.push(batch).unwrap();
        }
        let buffers = Arc::new(buffers);
        
        Self { buffers}
    }
    
    pub fn acquire(&self) -> Option<BatchHandle> {
        let buf = self.buffers.pop()?;
        Some(BatchHandle::new(self.buffers.clone(), buf))
    }
    
    // fn release(&self, mut buf: BytesMut) {
    //     // Очищаем буфер
    //     buf.clear();
        
    //     self.buffers.push(buf).unwrap();
    // }
}


pub struct BatchHandle 
{
    queue: Arc<ArrayQueue<Item>>,
    batch: Item,
}

impl BatchHandle 

{
    fn new(queue: Arc<ArrayQueue<Item>>, batch: Item) -> Self {
        Self { queue, batch }
    }

    pub fn inner(&self) -> &Item {
        &self.batch
    }

    pub fn inner_mut(&mut self) -> &mut Item {
        &mut self.batch
    }

}



impl Drop for BatchHandle 
{
    fn drop(&mut self) {
        let buf = std::mem::take(&mut self.batch);
        self.queue.push(buf).unwrap();
    }
}


// impl ExpandBuffer for PoolHandle {
//     fn buf_capacity(&self) -> usize {
//         self.buf.capacity()
//     }

//     fn buf_resize(&mut self, new_len: usize, value: u8) {
//         self.buf.resize(new_len, value);
//     }

//     fn buf_extend_from_slice(&mut self, src: &[u8]) {
//         self.buf.extend_from_slice(src);
//     }
// }
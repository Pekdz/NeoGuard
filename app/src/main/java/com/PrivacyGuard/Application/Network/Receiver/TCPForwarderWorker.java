package com.PrivacyGuard.Application.Network.Receiver;

import com.PrivacyGuard.Application.Network.Forwader.TCPForwarder;
import com.PrivacyGuard.Application.Network.LocalServer;
import com.PrivacyGuard.Application.PrivacyGuard;

import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Iterator;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * Created by y59song on 03/04/14.
 */
public class TCPForwarderWorker extends Thread {
  private final String TAG = "TCPForwarderWorker";
  private final int limit = 1368;
  private SocketChannel socketChannel;
  private Selector selector;
  private TCPForwarder forwarder;
  private ByteBuffer msg = ByteBuffer.allocate(limit);
  private ConcurrentLinkedQueue<byte[]> requests = new ConcurrentLinkedQueue<byte[]>();
  private Sender sender;

  public TCPForwarderWorker(InetAddress srcAddress, int src_port, InetAddress dstAddress, int dst_port, TCPForwarder forwarder) {
    this.forwarder = forwarder;
    try {
      socketChannel = SocketChannel.open();
      Socket socket = socketChannel.socket();
      socket.setReuseAddress(true);
      socket.bind(new InetSocketAddress(InetAddress.getLocalHost(), src_port));
      try {
        socketChannel.connect(new InetSocketAddress(LocalServer.port));
        while (!socketChannel.finishConnect()) ;
      } catch (ConnectException e) {
        e.printStackTrace();
        return;
      }
      socketChannel.configureBlocking(false);
      selector = Selector.open();
      socketChannel.register(selector, SelectionKey.OP_READ);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public boolean isValid() {
    return selector != null;
  }

  public void send(byte[] request) {
    requests.offer(request);
  }

  @Override
  public void run() {
    sender = new Sender();
    sender.start();
    while (!isInterrupted() && selector.isOpen()) {
      try {
        selector.select(0);
      } catch (IOException e) {
        e.printStackTrace();
      }
      Iterator<SelectionKey> iterator = selector.selectedKeys().iterator();
      while (!isInterrupted() && iterator.hasNext()) {
        SelectionKey key = iterator.next();
        iterator.remove();
        if (!key.isValid()) continue;
        else if (key.isReadable()) {
          try {
            msg.clear();
            int length = socketChannel.read(msg);
            if (length <= 0 || isInterrupted()) {
              close();
              return;
            }
            msg.flip();
            byte[] temp = new byte[length];
            msg.get(temp);
            PrivacyGuard.tcpForwarderWorkerRead += length;
            forwarder.forwardResponse(temp);
          } catch (IOException e) {
            e.printStackTrace();
          }
        }
      }
    }
    close();
  }

  public void close() {
    try {
      if (selector != null) selector.close();
    } catch (IOException e) {
      e.printStackTrace();
    }
    if (sender != null && sender.isAlive()) {
      sender.interrupt();
    }
    try {
      if (socketChannel.isConnected()) {
        socketChannel.socket().close();
        socketChannel.close();
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public class Sender extends Thread {
    public void run() {
      try {
        byte[] temp;
        while (!isInterrupted() && !socketChannel.socket().isClosed()) {
          while ((temp = requests.poll()) == null) {
            Thread.sleep(10);
          }
          ByteBuffer tempBuf = ByteBuffer.wrap(temp);
          while (true) {
            PrivacyGuard.tcpForwarderWorkerWrite += socketChannel.write(tempBuf);
            if (tempBuf.hasRemaining()) {
              Thread.sleep(10);
            } else break;
          }
        }
      } catch (InterruptedException e) {
        e.printStackTrace();
        return;
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }
}
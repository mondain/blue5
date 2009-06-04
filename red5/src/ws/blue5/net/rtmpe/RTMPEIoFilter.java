package ws.blue5.net.rtmpe;

/*
 * Blue5 media server support library - http://www.blue5.ws/
 * 
 * Copyright (c) 2009 by respective authors. All rights reserved.
 * 
 * This library is free software; you can redistribute it and/or modify it under the 
 * terms of the GNU Lesser General Public License as published by the Free Software 
 * Foundation; either version 2.1 of the License, or (at your option) any later 
 * version. 
 * 
 * This library is distributed in the hope that it will be useful, but WITHOUT ANY 
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A 
 * PARTICULAR PURPOSE. See the GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License along 
 * with this library; if not, write to the Free Software Foundation, Inc., 
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
 */

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.filterchain.IoFilterAdapter;
import org.apache.mina.core.filterchain.IoFilter.NextFilter;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.write.WriteRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ws.blue5.RtmpSession;

public class RTMPEIoFilter extends IoFilterAdapter {

	private static final Logger logger = LoggerFactory
			.getLogger(RTMPEIoFilter.class);

	@Override
	public void messageReceived(NextFilter nextFilter, IoSession ioSession,
			Object message) throws Exception {
		RtmpSession session = RtmpSession.getFrom(ioSession);
		if (!session.isEncrypted() || !session.isHandshakeComplete()
				|| !(message instanceof IoBuffer)) {
			if (logger.isDebugEnabled()) {
				logger.debug("not decrypting message received");
			}
			nextFilter.messageReceived(ioSession, message);
			return;
		}
		IoBuffer in = (IoBuffer) message;
		byte[] encrypted = new byte[in.remaining()];
		in.get(encrypted);
		if (logger.isDebugEnabled()) {
			in.rewind();
			logger.debug("decrypting buffer: " + in);
		}
		in.release();
		byte[] plain = session.getCipherIn().update(encrypted);
		IoBuffer out = IoBuffer.wrap(plain);
		if (logger.isDebugEnabled()) {
			logger.debug("decrypted buffer: " + out);
		}
		nextFilter.messageReceived(ioSession, out);
	}

	@Override
	public void filterWrite(NextFilter nextFilter, IoSession ioSession,
			WriteRequest writeRequest) throws Exception {
		RtmpSession session = RtmpSession.getFrom(ioSession);
		if (!session.isEncrypted() || !session.isHandshakeComplete()) {
			if (logger.isDebugEnabled()) {
				logger.debug("not encrypting write request");
			}
			nextFilter.filterWrite(ioSession, writeRequest);
			return;
		}

		IoBuffer in = (IoBuffer) writeRequest.getMessage();
		if (!in.hasRemaining()) {
			// Ignore empty buffers
			nextFilter.filterWrite(ioSession, writeRequest);
		} else {
			if (logger.isDebugEnabled()) {
				logger.debug("encrypting buffer: " + in);
			}
			byte[] plain = new byte[in.remaining()];
			in.get(plain);
			in.release();
			byte[] encrypted = session.getCipherOut().update(plain);
			IoBuffer out = IoBuffer.wrap(encrypted);
			if (logger.isDebugEnabled()) {
				logger.debug("encrypted buffer: " + out);
			}
			nextFilter.filterWrite(ioSession, new WriteRequest(out,
					writeRequest.getFuture()));
		}
	}

}

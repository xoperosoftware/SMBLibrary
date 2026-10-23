/* Copyright (C) 2017 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */
using System;
using System.Collections.Generic;
using Utilities;

namespace SMBLibrary.SMB2
{
    /// <summary>
    /// SMB2 READ Response
    /// </summary>
    public class ReadResponse : SMB2Command
    {
        public const int FixedSize = 16;
        public const int DeclaredSize = 17;

        private ushort StructureSize;
        private byte DataOffset;
        public byte Reserved;
        private uint DataLength;
        public uint DataRemaining;
        public uint Reserved2;
        public byte[] Data = new byte[0];

        // Holds the data in place of Data when the response was parsed from a pooled message, so it is not copied twice.
        private PooledBuffer m_message;
        private int m_messageDataOffset;

        public ReadResponse() : base(SMB2CommandName.Read)
        {
            Header.IsResponse = true;
            StructureSize = DeclaredSize;
        }

        public ReadResponse(byte[] buffer, int offset) : base(buffer, offset)
        {
            ReadFixedFields(buffer, offset);
            if (DataLength > 0)
            {
                Data = ByteReader.ReadBytes(buffer, offset + DataOffset, (int)DataLength);
            }
        }

        /// <remarks>Takes ownership of message; ReleaseData must be called once its data is no longer needed.</remarks>
        internal ReadResponse(PooledBuffer message) : base(message.Array, 0)
        {
            ReadFixedFields(message.Array, 0);
            if (DataOffset + (long)DataLength > message.Length)
            {
                throw new System.IO.InvalidDataException("READ response data exceeds the message");
            }
            m_message = message;
            m_messageDataOffset = DataOffset;
        }

        private void ReadFixedFields(byte[] buffer, int offset)
        {
            StructureSize = LittleEndianConverter.ToUInt16(buffer, offset + SMB2Header.Length + 0);
            DataOffset = ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 2);
            Reserved = ByteReader.ReadByte(buffer, offset + SMB2Header.Length + 3);
            DataLength = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 4);
            DataRemaining = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 8);
            Reserved2 = LittleEndianConverter.ToUInt32(buffer, offset + SMB2Header.Length + 12);
        }

        internal int DataCount
        {
            get
            {
                return m_message != null ? (int)DataLength : Data.Length;
            }
        }

        internal void CopyData(byte[] destination, int destinationOffset)
        {
            if (m_message != null)
            {
                Array.Copy(m_message.Array, m_messageDataOffset, destination, destinationOffset, (int)DataLength);
            }
            else
            {
                Array.Copy(Data, 0, destination, destinationOffset, Data.Length);
            }
        }

        /// <summary>
        /// Moves pooled data into Data, for callers of the API that hands out a byte[].
        /// </summary>
        internal void MaterializeData()
        {
            if (m_message != null)
            {
                Data = ByteReader.ReadBytes(m_message.Array, m_messageDataOffset, (int)DataLength);
                ReleaseData();
            }
        }

        internal void ReleaseData()
        {
            PooledBuffer message = m_message;
            m_message = null;
            if (message != null)
            {
                message.Dispose();
            }
        }

        public override void WriteCommandBytes(byte[] buffer, int offset)
        {
            DataOffset = 0;
            DataLength = (uint)Data.Length;
            if (Data.Length > 0)
            {
                DataOffset = SMB2Header.Length + FixedSize;
            }
            LittleEndianWriter.WriteUInt16(buffer, offset + 0, StructureSize);
            ByteWriter.WriteByte(buffer, offset + 2, DataOffset);
            ByteWriter.WriteByte(buffer, offset + 3, Reserved);
            LittleEndianWriter.WriteUInt32(buffer, offset + 4, DataLength);
            LittleEndianWriter.WriteUInt32(buffer, offset + 8, DataRemaining);
            LittleEndianWriter.WriteUInt32(buffer, offset + 12, Reserved2);
            if (Data.Length > 0)
            {
                ByteWriter.WriteBytes(buffer, offset + FixedSize, Data);
            }
        }

        public override int CommandLength
        {
            get
            {
                return FixedSize + Data.Length;
            }
        }
    }
}

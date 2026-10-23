using System;
using System.Buffers;
using System.Threading;

namespace SMBLibrary
{
    /// <summary>
    /// A packet-sized buffer rented from a pool shared by all connections, returned on Dispose.
    /// </summary>
    /// <remarks>
    /// Array is usually longer than Length and holds bytes left by its previous user.
    /// </remarks>
    internal sealed class PooledBuffer : IDisposable
    {
        // ArrayPool<byte>.Shared stops pooling at 1 MB on .NET 6, just below a 1 MB read or write plus its headers.
        private const int MaxPooledLength = 2 * 1024 * 1024;
        private const int MaxBuffersPerSize = 64;

        private static readonly ArrayPool<byte> s_pool = ArrayPool<byte>.Create(MaxPooledLength, MaxBuffersPerSize);

        private byte[] m_array;

        private PooledBuffer(byte[] array, int length)
        {
            m_array = array;
            Length = length;
        }

        /// <summary>
        /// Rents a buffer able to hold length bytes.
        /// </summary>
        public static PooledBuffer Rent(int length)
        {
            return new PooledBuffer(s_pool.Rent(length), length);
        }

        /// <summary>
        /// The rented array.
        /// </summary>
        public byte[] Array
        {
            get
            {
                byte[] array = m_array ?? throw new ObjectDisposedException(nameof(PooledBuffer));
                return array;
            }
        }

        /// <summary>
        /// The number of bytes the buffer was rented for.
        /// </summary>
        public int Length { get; }

        /// <summary>
        /// Returns the array to the pool; later calls do nothing.
        /// </summary>
        public void Dispose()
        {
            // A second Dispose must not hand the same array to two renters.
            byte[] array = Interlocked.Exchange(ref m_array, null);
            if (array != null)
            {
                s_pool.Return(array);
            }
        }
    }
}

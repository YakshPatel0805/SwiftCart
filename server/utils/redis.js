import { createClient } from 'redis';
import dotenv from 'dotenv';

dotenv.config();

const redisClient = createClient({
  url: process.env.REDIS_URI || 'redis://localhost:6379',
  socket: {
    reconnectStrategy: (retries) => {
      // Limit retries to prevent infinite error loop when Redis is down
      if (retries > 3) {
        console.warn('⚠️  Redis is not running. Caching will gracefully fall back to MongoDB.');
        return new Error('Redis fallback'); // Short error just to break the loop
      }
      return Math.min(retries * 100, 3000); // Reconnect after a short delay
    }
  }
});

redisClient.on('error', (err) => {
  // We swallow the spammy connection errors since we handle it gracefully above
});

redisClient.on('connect', () => {
  console.log('Connected to Redis');
});

export const connectRedis = async () => {
  try {
    if (!redisClient.isOpen) {
      await redisClient.connect();
    }
  } catch (error) {
    // Suppress stack trace on failed connection
    console.log('ℹ️  Redis connection closed (Caching disabled).');
  }
};

export default redisClient;

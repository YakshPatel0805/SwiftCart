import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/SwiftCart';

async function initializeDatabase() {
  try {
    console.log('Connecting to MongoDB...');
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    // Get the database
    const db = mongoose.connection.db;

    // Create collections if they don't exist
    const collections = [
      'users',
      'products',
      'orders',
      'payments',
      'banks',
      'wishlists',
      'deliveryrequests',
      'contacts'
    ];

    for (const collectionName of collections) {
      try {
        await db.createCollection(collectionName);
        console.log(`✅ Created collection: ${collectionName}`);
      } catch (error) {
        if (error.codeName === 'NamespaceExists') {
          console.log(`ℹ️  Collection already exists: ${collectionName}`);
        } else {
          console.error(`❌ Error creating collection ${collectionName}:`, error.message);
        }
      }
    }

    // Create indexes
    console.log('\nCreating indexes...');
    
    const User = mongoose.model('User', new mongoose.Schema({
      email: { type: String, unique: true },
      username: { type: String, unique: true }
    }));

    const Product = mongoose.model('Product', new mongoose.Schema({
      name: String,
      category: String
    }));

    const Order = mongoose.model('Order', new mongoose.Schema({
      userId: mongoose.Schema.Types.ObjectId,
      createdAt: Date
    }));

    try {
      await User.collection.createIndex({ email: 1 });
      console.log('✅ Created index on users.email');
    } catch (error) {
      console.log('ℹ️  Index already exists on users.email');
    }

    try {
      await User.collection.createIndex({ username: 1 });
      console.log('✅ Created index on users.username');
    } catch (error) {
      console.log('ℹ️  Index already exists on users.username');
    }

    try {
      await Product.collection.createIndex({ category: 1 });
      console.log('✅ Created index on products.category');
    } catch (error) {
      console.log('ℹ️  Index already exists on products.category');
    }

    try {
      await Order.collection.createIndex({ userId: 1 });
      console.log('✅ Created index on orders.userId');
    } catch (error) {
      console.log('ℹ️  Index already exists on orders.userId');
    }

    console.log('\n✅ Database initialization complete!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Database initialization failed:', error);
    process.exit(1);
  }
}

initializeDatabase();

import { MongoClient } from 'mongodb';

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';

async function initializeDatabase() {
  let client;
  try {
    console.log('Connecting to MongoDB...');
    client = new MongoClient(MONGODB_URI);
    await client.connect();
    console.log('✅ Connected to MongoDB');

    // Get the database
    const db = client.db('SwiftCart');

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

    console.log('\nCreating collections...');
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
    
    try {
      await db.collection('users').createIndex({ email: 1 }, { unique: true });
      console.log('✅ Created unique index on users.email');
    } catch (error) {
      console.log('ℹ️  Index already exists on users.email');
    }

    try {
      await db.collection('users').createIndex({ username: 1 }, { unique: true });
      console.log('✅ Created unique index on users.username');
    } catch (error) {
      console.log('ℹ️  Index already exists on users.username');
    }

    try {
      await db.collection('products').createIndex({ category: 1 });
      console.log('✅ Created index on products.category');
    } catch (error) {
      console.log('ℹ️  Index already exists on products.category');
    }

    try {
      await db.collection('orders').createIndex({ userId: 1 });
      console.log('✅ Created index on orders.userId');
    } catch (error) {
      console.log('ℹ️  Index already exists on orders.userId');
    }

    console.log('\n✅ Database initialization complete!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Database initialization failed:', error.message);
    process.exit(1);
  } finally {
    if (client) {
      await client.close();
    }
  }
}

initializeDatabase();

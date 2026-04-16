# MongoDB Compass Connection Guide

## 🔗 Connect MongoDB Compass to Docker MongoDB

### Connection Details

- **Host**: `localhost`
- **Port**: `27017`
- **No Authentication Required** (Local Development)

### Step-by-Step Instructions

#### 1. Open MongoDB Compass

Launch MongoDB Compass on your machine.

#### 2. Create New Connection

Click on **"New Connection"** or **"+"** button.

#### 3. Enter Connection String

Use this connection string:
```
mongodb://localhost:27017
```

Or fill in the fields:
- **Host**: `localhost`
- **Port**: `27017`
- **Leave Username and Password empty**

#### 4. Connect

Click **"Connect"** button.

#### 5. View Databases

You should now see:
- ✅ `SwiftCart` - Your application database
- `admin` - System database
- `config` - System database
- `local` - System database

### Collections in SwiftCart Database

Once connected, expand the `SwiftCart` database to see:

- `banks` - Payment method information
- `contacts` - Contact form submissions
- `deliveryrequests` - Delivery requests
- `orders` - Customer orders
- `payments` - Payment records
- `products` - Product catalog
- `users` - User accounts
- `wishlists` - User wishlists

### Troubleshooting

#### Connection Refused

**Problem**: "Connection refused" error

**Solution**:
1. Verify Docker containers are running: `docker-compose ps`
2. Ensure MongoDB container is healthy
3. Check port 27017 is not blocked by firewall
4. Verify connection string is correct: `mongodb://localhost:27017`

#### Database Not Showing

**Problem**: SwiftCart database doesn't appear

**Solution**:
1. Verify db-init service ran successfully: `docker-compose logs db-init`
2. Check collections were created: `docker-compose exec mongodb mongosh --eval "use SwiftCart; show collections"`
3. Restart services: `docker-compose restart`

### Verify Connection from Command Line

```bash
# Connect to MongoDB (no authentication needed)
docker-compose exec mongodb mongosh

# In mongosh shell:
> show dbs
> use SwiftCart
> show collections
> db.users.find()
```

### Security Notes

- **Development Only**: MongoDB runs without authentication for local development
- **Change in Production**: Enable authentication and use strong credentials for production
- **Network Access**: MongoDB is only accessible on localhost in Docker

### Connection Examples

#### Python (PyMongo)
```python
from pymongo import MongoClient

client = MongoClient('mongodb://localhost:27017')
db = client['SwiftCart']
users = db['users'].find()
```

#### Node.js (Mongoose)
```javascript
const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost:27017/SwiftCart');
```

#### JavaScript (MongoDB Driver)
```javascript
const { MongoClient } = require('mongodb');

const client = new MongoClient('mongodb://localhost:27017');
await client.connect();
const db = client.db('SwiftCart');
```

### Common Operations in Compass

#### View Documents
1. Click on collection name
2. Documents appear in the right panel
3. Click on any document to expand details

#### Insert Document
1. Click collection name
2. Click **"Insert Document"** button
3. Enter JSON data
4. Click **"Insert"**

#### Update Document
1. Click on document
2. Click **"Edit"** button
3. Modify fields
4. Click **"Update"**

#### Delete Document
1. Click on document
2. Click **"Delete"** button
3. Confirm deletion

#### Create Index
1. Click collection name
2. Go to **"Indexes"** tab
3. Click **"Create Index"**
4. Select fields and options
5. Click **"Create"**

### Performance Tips

- Use indexes for frequently queried fields
- Limit document size for better performance
- Archive old data periodically
- Monitor collection sizes

### Next Steps

1. ✅ Connect to MongoDB Compass
2. ✅ Explore the SwiftCart database
3. ✅ View collections and documents
4. ✅ Test CRUD operations
5. ✅ Monitor data in real-time

---

**Happy exploring! 🎉**

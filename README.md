# E-Commerce Application with MongoDB

Full-stack e-commerce application with React frontend and Node.js/Express backend using MongoDB.

## Features

- User authentication with bcrypt password hashing
- JWT token-based authorization
- Product catalog stored in MongoDB
- User wishlist functionality
- Admin panel with CSV product upload
- Role-based access control (Admin/User)
- Secure API endpoints

## Prerequisites

- Node.js (v16 or higher)
- MongoDB (local or MongoDB Atlas)
- npm or yarn

## Setup Instructions

### 1. Backend Setup

```bash
cd server
npm install
```

Create a `.env` file in the server directory:

```env
MONGODB_URI=mongodb://localhost:27017/ecommerce
JWT_SECRET=your_secure_jwt_secret_key_here
PORT=5000
```

For MongoDB Atlas, use your connection string:
```env
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/ecommerce
```

### 2. Create Admin User

```bash
cd server
npm run create-admin
```

Or with custom credentials:
```bash
npm run create-admin admin@example.com admin admin123
```

This creates an admin user who can upload products via CSV.

### 3. Seed Database (Optional)

```bash
cd server
npm run seed
```

### 4. Start Backend Server

```bash
cd server
npm run dev
```

Server will run on http://localhost:5000

### 5. Frontend Setup

```bash
npm install
npm run dev
```

Frontend will run on http://localhost:5173

## Admin Features

### CSV Product Upload

1. Login with admin credentials
2. Navigate to Admin Panel from user menu
3. Download CSV template or use the example file at `server/example_products.csv`
4. Upload your CSV file with products

### CSV Format

Required columns:
- `name` - Product name
- `price` - Price (number)
- `image` - Image URL
- `category` - Must be: clothing, electronics, or furniture
- `description` - Product description

Optional columns:
- `rating` - Rating 0-5 (default: 0)
- `reviews` - Number of reviews (default: 0)
- `inStock` - true/false (default: true)

Example CSV:
```csv
name,price,image,category,description,rating,reviews,inStock
Premium T-Shirt,29.99,https://example.com/img.jpg,clothing,Comfortable shirt,4.5,100,true
```

## API Endpoints

### Authentication
- `POST /api/auth/signup` - Register new user
- `POST /api/auth/login` - Login user

### Products
- `GET /api/products` - Get all products
- `GET /api/products/:id` - Get product by ID
- `POST /api/products` - Add product (Admin only)
- `POST /api/products/upload-csv` - Upload products via CSV (Admin only)
- `PUT /api/products/:id` - Update product (Admin only)
- `DELETE /api/products/:id` - Delete product (Admin only)

### Wishlist (Protected)
- `GET /api/wishlist` - Get user wishlist
- `POST /api/wishlist/:productId` - Add product to wishlist
- `DELETE /api/wishlist/:productId` - Remove product from wishlist

## User Roles

### Regular User
- Browse products
- Add to cart/wishlist
- Place orders
- View profile and order history

### Admin
- All user permissions
- Access to Admin Panel
- Upload products via CSV
- Add/Edit/Delete products
- View all orders

## Database Collections

### Users
- email (unique)
- username (unique)
- password (bcrypt hashed)
- role (user/admin)
- wishlist (array of product IDs)
- profile information

### Products
- name
- price
- image
- category
- description
- rating
- reviews
- inStock

## Security Features

- Passwords hashed with bcrypt (10 rounds)
- JWT tokens for authentication
- Role-based access control
- Protected API routes with middleware
- Admin-only endpoints for product management
- CORS enabled for frontend communication

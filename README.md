# E-Commerce Application with MongoDB

Full-stack e-commerce application with React frontend and Node.js/Express backend using MongoDB.

## Features

- User authentication with bcrypt password hashing
- JWT token-based authorization
- Product catalog stored in MongoDB
- Shopping cart and checkout functionality
- User wishlist functionality
- Order management with status tracking
- Email notifications for orders, payments, and cancellations
- Admin panel with CSV product upload
- Role-based access control (Admin/User)
- Secure API endpoints
- React Router for proper URL-based navigation

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

# Email Configuration (for order notifications)
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
```

For MongoDB Atlas, use your connection string:
```env
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/ecommerce
```

#### Email Setup (Gmail)

1. Enable 2-Step Verification on your Google Account
2. Generate an App Password at https://myaccount.google.com/apppasswords
3. Use the App Password in EMAIL_PASSWORD (not your regular password)
4. Set ADMIN_EMAIL to the email address where you want to receive admin notifications

See `server/EMAIL_COMPLETE_GUIDE.md` for detailed email configuration instructions.

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

### 3. Test Email Configuration (Optional)

```bash
cd server
npm run test-email
```

This will verify your email configuration is working correctly.

### 4. Seed Database (Optional)

```bash
cd server
npm run seed
```

### 5. Start Backend Server

```bash
cd server
npm run dev
```

Server will run on http://localhost:5000

### 6. Frontend Setup

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

### Orders (Protected)
- `GET /api/orders` - Get user orders
- `GET /api/orders/:id` - Get order by ID
- `POST /api/orders` - Create new order (sends confirmation email)
- `PATCH /api/orders/:id/cancel` - Cancel order (sends cancellation email)

## Email Notifications

The application automatically sends emails for:

### Customer Emails:

1. **Order Confirmation** - When a new order is placed
   - Includes order details, items, shipping address
   - Sent to the email provided in shipping address

2. **Payment Confirmation** - When payment is processed
   - Sent for Credit Card and Google Pay payments
   - Not sent for Cash on Delivery

3. **Order Cancellation** - When an order is cancelled
   - Includes refund information
   - Sent to the customer's email

### Admin Notifications:

4. **New Order Alert** - When a customer places an order
   - Sent to admin email (ADMIN_EMAIL in .env)
   - Includes complete order details, customer info, and shipping address
   - Helps admin track and process orders immediately

5. **Order Cancellation Alert** - When a customer cancels an order
   - Sent to admin email
   - Includes cancellation details and required actions
   - Helps admin stop processing and handle refunds

### Email Configuration

- Uses Nodemailer with Gmail SMTP
- Requires Gmail App Password (not regular password)
- HTML-formatted responsive emails
- Professional templates with branding
- Admin email configurable via ADMIN_EMAIL environment variable

See `server/EMAIL_COMPLETE_GUIDE.md` for detailed setup instructions.

## User Roles

### Regular User
- Browse products by category
- Search products
- Add to cart/wishlist
- Place orders with multiple payment methods
- Receive email notifications
- View profile and order history
- Cancel orders (before shipping)

### Admin
- All user permissions
- Access to Admin Panel
- Upload products via CSV
- Add/Edit/Delete products
- View all orders
- Manage user accounts

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
- category (clothing, electronics, furniture, appliances, beauty, accessories, stationery, books, sports, baby)
- description
- rating
- reviews
- inStock

### Orders
- userId (reference to User)
- items (array of products with quantities)
- total
- status (pending, processing, shipped, delivered, cancelled)
- shippingAddress
- paymentMethod (credit-card, google-pay, cash-on-delivery)
- createdAt

## Security Features

- Passwords hashed with bcrypt (10 rounds)
- JWT tokens for authentication
- Role-based access control
- Protected API routes with middleware
- Admin-only endpoints for product management
- CORS enabled for frontend communication

# E-Commerce Application

A full-stack e-commerce platform built with React, Node.js, Express, and MongoDB featuring comprehensive user management, payment processing, and order fulfillment.

## 🚀 Features

### Core Functionality
- **User Authentication**: Secure signup/login with JWT tokens and bcrypt password hashing
- **Product Management**: Browse, search, and filter products by category
- **Shopping Cart & Wishlist**: Add/remove items with persistent storage
- **Order Management**: Complete order lifecycle with status tracking
- **Payment Processing**: Multiple payment methods (Credit Card, Bank Transfer, Google Pay, Cash on Delivery)
- **Email Notifications**: Automated order confirmations and admin alerts

### User Roles
- **Customers**: Browse, shop, manage profile and payment methods
- **Admins**: Product management, user role assignment, CSV bulk uploads
- **Delivery Personnel**: Order status updates, delivery request management

### Advanced Features
- **Profile Management**: Edit personal information and manage payment accounts
- **Bank Account Integration**: Store multiple payment methods securely
- **Real-time Order Tracking**: Live status updates from processing to delivery
- **Admin Dashboard**: Comprehensive management interface
- **CSV Product Import**: Bulk product uploads with validation

## 🛠️ Tech Stack

**Frontend:**
- React 18 with TypeScript
- Vite for development and building
- React Router for navigation
- Tailwind CSS for styling
- Lucide React for icons

**Backend:**
- Node.js with Express
- MongoDB with Mongoose ODM
- JWT for authentication
- Nodemailer for email services
- Multer for file uploads

## 📋 Prerequisites

- Node.js (v16 or higher)
- MongoDB (local installation or MongoDB Atlas)
- npm or yarn package manager

## ⚡ Quick Start

### 1. Clone and Install

```bash
git clone <repository-url>
cd SwiftCart
npm install
cd server && npm install && cd ..
```

### 2. Environment Configuration

Create `server/.env`:

```env
MONGODB_URI=mongodb://localhost:27017/ecommerce
JWT_SECRET=your_secure_jwt_secret_key_here
PORT=5000
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-gmail-app-password
ADMIN_EMAIL=admin@yourcompany.com
```

### 3. Start Development Servers

```bash
npm start
```

This single command starts both frontend (port 5173) and backend (port 5000) concurrently.

### 4. Create Admin Account

1. Sign up with these credentials:
   - **Username**: `admin`
   - **Password**: `admin123`
   - **Email**: Use the same email as `ADMIN_EMAIL` in your `.env`

## 📧 Email Setup (Gmail)

1. Enable 2-Step Verification on your Google Account
2. Generate App Password at [Google App Passwords](https://myaccount.google.com/app-passwords)
3. Use the App Password in `EMAIL_PASSWORD` (not your regular password)

For detailed email configuration, see `server/EMAIL_COMPLETE_GUIDE.md`.

## 📊 Admin Features

### CSV Product Upload
1. Login as admin
2. Navigate to Admin Panel
3. Download CSV template or use `server/example_products.csv`
4. Upload your product file

**Required CSV Columns:**
```csv
name,price,image,category,description,rating,reviews,inStock
Premium T-Shirt,29.99,https://example.com/img.jpg,clothing,Comfortable cotton shirt,4.5,Great quality,true
```

**Categories:** `clothing`, `electronics`, `furniture`

### User Management
- Assign delivery personnel roles
- View all user accounts
- Manage user permissions

## 🔐 API Documentation

### Authentication
```
POST /api/auth/signup    - Register new user
POST /api/auth/login     - User login
```

### Products
```
GET    /api/products           - Get all products
GET    /api/products/:id       - Get product by ID
POST   /api/products           - Add product (Admin)
POST   /api/products/upload-csv - CSV upload (Admin)
PUT    /api/products/:id       - Update product (Admin)
DELETE /api/products/:id       - Delete product (Admin)
```

### Orders (Protected)
```
GET    /api/orders        - Get user orders
GET    /api/orders/:id    - Get specific order
POST   /api/orders        - Create new order
PATCH  /api/orders/:id/cancel - Cancel order
```

### Payment Methods (Protected)
```
GET    /api/bank          - Get user payment methods
POST   /api/bank          - Add payment method
DELETE /api/bank/:type    - Remove payment method
PATCH  /api/bank/:type/set-default - Set default payment
```

### Payments (Protected)
```
POST /api/payments/creditcard      - Process credit card payment
POST /api/payments/accounttransfer - Process bank transfer
POST /api/payments/create-with-*   - Create order with payment
```

## 💳 Payment Methods

### Supported Types
- **Credit Card**: Visa, Mastercard, American Express
- **Bank Transfer**: Direct account transfer
- **Google Pay**: UPI-based payments
- **Cash on Delivery**: Pay upon delivery

### Test Credit Cards
```
4539 1488 0343 6467 — Visa
4485 2757 4323 8327 — Visa  
5555 5555 5555 4444 — Mastercard
5105 1051 0510 5100 — Mastercard
3782 822463 10005   — American Express
```

## 📧 Email Notifications

### Customer Emails
- **Order Confirmation**: Complete order details and tracking info
- **Payment Confirmation**: Payment receipt for card/digital payments
- **Order Cancellation**: Cancellation confirmation with refund details

### Admin Notifications
- **New Order Alerts**: Immediate notification of new orders
- **Cancellation Alerts**: Order cancellation notifications for processing

## 🗄️ Database Schema

### Users Collection
```javascript
{
  email: String (unique),
  username: String (unique),
  password: String (hashed),
  role: String (user/admin/deliveryboy),
  wishlist: [ObjectId]
}
```

### Products Collection
```javascript
{
  name: String,
  price: Number,
  image: String,
  category: String,
  description: String,
  rating: Number,
  reviews: String,
  inStock: Boolean
}
```

### Orders Collection
```javascript
{
  userId: ObjectId,
  items: [{productId, quantity, price}],
  total: Number,
  status: String,
  shippingAddress: Object,
  paymentMethod: String,
  createdAt: Date
}
```

### Bank Collection
```javascript
{
  userId: ObjectId,
  username: String,
  bankAccount: {
    accountHolderName: String,
    accountNumber: String,
    accountPIN: String,
    balance: Number,
    isDefault: Boolean
  },
  creditCard: {
    cardHolderName: String,
    cardNumber: String,
    cardCVV: String,
    cardExpiry: String,
    cardBalance: Number,
    isDefault: Boolean
  },
  googlePay: {
    mobileNumber: String,
    upiId: String,
    PIN: String,
    balance: Number,
    isDefault: Boolean
  }
}
```

## 🔒 Security Features

- **Password Security**: bcrypt hashing with 10 rounds
- **JWT Authentication**: Secure token-based auth
- **Role-based Access**: Granular permission system
- **API Protection**: Middleware-protected routes
- **CORS Configuration**: Secure cross-origin requests
- **Input Validation**: Server-side data validation

## 🚀 Deployment

### Production Build
```bash
npm run build
```

### Environment Variables (Production)
Ensure all environment variables are set in your production environment, especially:
- `MONGODB_URI` (MongoDB Atlas connection string)
- `JWT_SECRET` (strong, unique secret)
- Email configuration for notifications

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Check the documentation in `/server/EMAIL_COMPLETE_GUIDE.md`
- Review the example files in `/server/example_products.csv`
- Open an issue for bug reports or feature requests

---

**Happy Shopping! 🛒**
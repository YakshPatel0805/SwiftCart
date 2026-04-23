# SwiftCart Project Structure

## Overview
SwiftCart is a full-stack e-commerce application built with React (frontend) and Node.js/Express (backend).

## Root Directory Structure

```
SwiftCart/
├── src/                          # Frontend React application
├── server/                       # Backend Node.js/Express application
├── index.html                    # HTML entry point
```

---

## Frontend Structure (`src/`)

### Main Files
```
src/
├── main.tsx                     # Application entry point
├── App.tsx                      # Root component with routing
├── index.css                    # Global styles
```

### Components (`src/components/`)
```
src/components/
├── Layout/
│   ├── Header.tsx              # Main navigation header (for users)
│   ├── AdminHeader.tsx         # Admin navigation header
│   └── Footer.tsx              # Footer component
│
└── Product/
    ├── ProductCard.tsx         # Individual product card
    └── ProductGrid.tsx         # Grid layout for products
```

### Pages (`src/pages/`)
```
src/pages/
├── Home.tsx                    # Landing page with hero & categories
├── Dashboard.tsx               # User dashboard
├── Profile.tsx                 # User profile with role display
├── About.tsx                   # About page
├── Contact.tsx                 # Contact page
├── Help.tsx                    # Help page
├── Privacy.tsx                 # Privacy policy
├── Terms.tsx                   # Terms of service
├── Debug.tsx                   # Debug utilities
│
├── Auth/
│   ├── Login.tsx              # Login page
│   └── Signup.tsx             # Registration page
│
├── CategoryPage.tsx           # Dynamic category product listing
├── SearchResults.tsx          # Search results page
│
├── Cart.tsx                   # Shopping cart
├── Checkout.tsx               # Checkout process
├── Orders.tsx                 # User order history
├── Wishlist.tsx               # User wishlist
│
└── Admin/
    ├── AdminPanel.tsx         # Admin dashboard & product creation
    ├── AdminProductsView.tsx  # Product management with filters
    └── AdminOrdersView.tsx    # Order management with status updates
```

### Context (`src/context/`)
```
src/context/
├── AuthContext.tsx            # Authentication state & user management
├── CartContext.tsx            # Shopping cart state management
└── WishlistContext.tsx        # Wishlist state management
```

### Services (`src/services/`)
```
src/services/
└── api.ts                     # API client with endpoints:
                               # - authAPI (signup, login)
                               # - productsAPI (getAll, getById, getCategories)
                               # - ordersAPI (getAll, getAllAdmin, create, cancel, updateStatus, requestReturn)
                               # - wishlistAPI (get, add, remove)
```

### Types (`src/types/`)
```
src/types/
└── index.ts                   # TypeScript interfaces:
                               # - User, Product, CartItem, Order
                               # - ShippingAddress, PaymentMethod
```

### Data (`src/data/`)
```
src/data/
└── products.ts                # Static product data (if used)
```

---

## Backend Structure (`server/`)

### Main Files
```
server/
├── server.js                  # Express server entry point
├── package.json               # Backend dependencies
├── package-lock.json          # Backend dependency lock
├── .env                       # Environment variables (not in git)
├── .gitignore                 # Backend-specific ignore rules
├── testEmail.js               # Email service testing utility
└── example_products.csv       # Sample product data
```

### Models (`server/models/`)
```
server/models/
├── User.js                    # User schema (email, username, password, role, wishlist)
├── Product.js                 # Product schema (name, price, category, image, etc.)
└── Order.js                   # Order schema (userId, items, status, shipping, payment)
```

### Routes (`server/routes/`)
```
server/routes/
├── auth.js                    # Authentication routes:
│                              # - POST /api/auth/signup
│                              # - POST /api/auth/login
│
├── products.js                # Product routes:
│                              # - GET /api/products
│                              # - GET /api/products/categories
│                              # - GET /api/products/:id
│                              # - POST /api/products (admin)
│                              # - PUT /api/products/:id (admin)
│                              # - DELETE /api/products/:id (admin)
│
├── orders.js                  # Order routes:
│                              # - GET /api/orders (user's orders)
│                              # - GET /api/orders/admin/all (admin)
│                              # - GET /api/orders/:id
│                              # - POST /api/orders
│                              # - PATCH /api/orders/:id/cancel
│                              # - PATCH /api/orders/:id/request-return
│                              # - PATCH /api/orders/:id/status (admin)
│
└── wishlist.js                # Wishlist routes:
                               # - GET /api/wishlist
                               # - POST /api/wishlist/:productId
                               # - DELETE /api/wishlist/:productId
```

### Middleware (`server/middleware/`)
```
server/middleware/
├── auth.js                    # JWT authentication middleware
└── adminAuth.js               # Admin role verification middleware
```

### Utils (`server/utils/`)
```
server/utils/
└── emailService.js            # Email notifications:
                               # - Order confirmation
                               # - Order cancellation
                               # - Refund confirmation
                               # - Payment confirmation
                               # - Admin notifications
```

### Scripts (`server/scripts/`)
```
server/scripts/
├── createAdmin.js             # Create admin user utility
└── seedProducts.js            # Seed database with products from CSV
```

---

## Key Features by Module

### Authentication & Authorization
- **Files**: `AuthContext.tsx`, `auth.js` (routes), `auth.js` (middleware), `adminAuth.js`
- JWT-based authentication
- Role-based access control (user/admin)
- Protected routes

### Product Management
- **Files**: `Product.js`, `products.js`, `AdminPanel.tsx`, `AdminProductsView.tsx`
- Dynamic categories (any string accepted)
- CRUD operations (admin only)
- Category filtering and search
- Stock management

### Shopping Cart
- **Files**: `CartContext.tsx`, `Cart.tsx`, `Checkout.tsx`
- Add/remove/update quantities
- Persistent cart state
- Checkout with multiple payment methods

### Order Management
- **Files**: `Order.js`, `orders.js`, `Orders.tsx`, `AdminOrdersView.tsx`
- Order creation with email notifications
- Order status tracking (pending, processing, shipped, delivered, cancelled, return-requested, refunded)
- Return request workflow (7-day window)
- Admin refund management with balance restoration
- Admin order management with status updates
- User order history

### Wishlist
- **Files**: `WishlistContext.tsx`, `Wishlist.tsx`, `wishlist.js`
- Add/remove products
- Persistent wishlist per user

### Admin Features
- **Files**: `AdminHeader.tsx`, `AdminPanel.tsx`, `AdminProductsView.tsx`, `AdminOrdersView.tsx`
- Separate admin navigation
- Product creation and management
- Order management with customer details
- Statistics dashboard

### Email Notifications
- **Files**: `emailService.js`
- Order confirmations
- Payment confirmations
- Order cancellations
- Refund confirmations
- Admin notifications

---

## Technology Stack

### Frontend
- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite
- **Styling**: Tailwind CSS
- **Routing**: React Router v6
- **Icons**: Lucide React
- **State Management**: Context API

### Backend
- **Runtime**: Node.js
- **Framework**: Express.js
- **Database**: MongoDB with Mongoose
- **Authentication**: JWT (jsonwebtoken)
- **Password Hashing**: bcryptjs
- **Email**: Nodemailer
- **Environment**: dotenv
- **Security**: CORS enabled

---

## Environment Variables

### Backend (`.env`)
```
PORT=5000
MONGODB_URI=mongodb://localhost:27017/swiftcart
JWT_SECRET=your_jwt_secret_key
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_app_password
ADMIN_EMAIL=_admin@gmail.com
```

---

## API Endpoints Summary

### Public Routes
- `POST /api/auth/signup` - User registration
- `POST /api/auth/login` - User login
- `GET /api/products` - Get all products
- `GET /api/products/categories` - Get all categories with counts
- `GET /api/products/:id` - Get single product

### User Routes (Authentication Required)
- `GET /api/orders` - Get user's orders
- `POST /api/orders` - Create new order
- `PATCH /api/orders/:id/cancel` - Cancel order
- `PATCH /api/orders/:id/request-return` - Request return (7 days)
- `GET /api/wishlist` - Get user's wishlist
- `POST /api/wishlist/:productId` - Add to wishlist
- `DELETE /api/wishlist/:productId` - Remove from wishlist

### Admin Routes (Admin Role Required)
- `POST /api/products` - Create product
- `PUT /api/products/:id` - Update product
- `DELETE /api/products/:id` - Delete product
- `GET /api/orders/admin/all` - Get all orders
- `PATCH /api/orders/:id/status` - Update order status
- `POST /api/payments/refund/:orderId` - Process refund

---

## User Roles & Access

### Regular User
- Browse products and categories
- Search products
- Add to cart and wishlist
- Place orders
- View order history
- Cancel orders (before shipped)
- Access: Home, Dashboard, Profile, Orders, Cart, Wishlist

### Admin User
- All user capabilities
- Create/edit/delete products
- View all customer orders
- Update order status
- View customer information
- Access: Admin Panel, Admin Products View, Admin Orders View
- Redirects to `/admin` on login

---

## How to Login as Admin

### Step 1: Create Admin User

You need to create an admin user first using the createAdmin script:

```bash
cd server
node scripts/createAdmin.js <email> <username> <password>
```

**Examples:**

```bash
# Using command line arguments
node scripts/createAdmin.js admin@example.com admin admin123

# Using environment variable (set ADMIN_EMAIL in .env)
node scripts/createAdmin.js
```

**Default values if not provided:**
- Email: From `ADMIN_EMAIL` in `.env` file
- Username: `admin`
- Password: `admin123`

### Step 2: Login

1. Start both frontend and backend servers
2. Go to the login page: `http://localhost:5173/login`
3. Enter the admin credentials you created
4. You will be automatically redirected to `/admin` (Admin Panel)

**Example Admin Credentials:**
- Email: `admin@example.com`
- Password: `admin123`

### Admin Features After Login

Once logged in as admin, you'll have access to:
- **Admin Panel** (`/admin`) - Dashboard with quick actions and product creation
- **Admin Products View** (`/admin/products`) - Manage all products with category filters
- **Admin Orders View** (`/admin/orders`) - View and manage all customer orders
- **Admin Header** - Special navigation bar (replaces regular header)

---

## Development Commands

### Frontend
```bash
npm install          # Install dependencies
npm run dev          # Start development server (port 5173)
npm run build        # Build for production
npm run preview      # Preview production build
```

### Backend
```bash
cd server
npm install          # Install dependencies
npm start            # Start server (port 5000)
node scripts/createAdmin.js <email> <username> <password>  # Create admin user
node scripts/seedProducts.js     # Seed products from CSV
node testEmail.js                # Test email service
```

---

## Notes

1. **Dynamic Categories**: The system supports any category string. Categories are automatically extracted from products.

2. **Admin Auto-Redirect**: Admin users are automatically redirected to `/admin` upon login.

3. **Email Notifications**: Configured for Gmail. Requires app-specific password.

4. **Security**: All sensitive routes are protected with JWT authentication and role-based middleware.

5. **Responsive Design**: All pages are mobile-responsive using Tailwind CSS.

6. **Loading States**: Implemented throughout the application for better UX.

7. **Error Handling**: Comprehensive error handling on both frontend and backend.

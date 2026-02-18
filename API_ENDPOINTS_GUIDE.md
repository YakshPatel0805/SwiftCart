# API Endpoints Guide

## Overview
This document provides details on all API endpoints, including how to use them and test them.

---

## Authentication

All protected routes require a JWT token in the Authorization header:
```
Authorization: Bearer <your_jwt_token>
```

Get the token by logging in via `/api/auth/login`

---

## Products API

### 1. Get All Products
```
GET /api/products
```
- **Auth**: Not required
- **Response**: Array of all products

### 2. Get Product by ID
```
GET /api/products/:id
```
- **Auth**: Not required
- **Response**: Single product object

### 3. Get Categories
```
GET /api/products/categories
```
- **Auth**: Not required
- **Response**: Array of categories with product counts
```json
[
  { "category": "clothing", "count": 15 },
  { "category": "electronics", "count": 8 }
]
```

### 4. Create Product (Admin Only)
```
POST /api/products
```
- **Auth**: Required (Admin)
- **Body**:
```json
{
  "name": "Product Name",
  "price": 99.99,
  "category": "electronics",
  "image": "https://example.com/image.jpg",
  "description": "Product description",
  "rating": 4.5,
  "reviews": 100,
  "inStock": true
}
```
- **Response**: Created product object

### 5. Update Product (Admin Only) ✅ NOW WORKING
```
PUT /api/products/:id
```
- **Auth**: Required (Admin)
- **Body**: Same as create (any fields you want to update)
- **Response**: Updated product object
- **Frontend**: Available in Admin Products View (Edit button)

### 6. Delete Product (Admin Only) ✅ NOW WORKING
```
DELETE /api/products/:id
```
- **Auth**: Required (Admin)
- **Response**: Success message
- **Frontend**: Available in Admin Products View (Delete button with confirmation)

---

## Orders API

### 1. Get User's Orders
```
GET /api/orders
```
- **Auth**: Required (User)
- **Response**: Array of user's orders

### 2. Get All Orders (Admin Only)
```
GET /api/orders/admin/all
```
- **Auth**: Required (Admin)
- **Response**: Array of all orders with user and product details

### 3. Get Order by ID
```
GET /api/orders/:id
```
- **Auth**: Required (User - own orders only)
- **Response**: Single order object

### 4. Create Order
```
POST /api/orders
```
- **Auth**: Required (User)
- **Body**:
```json
{
  "items": [
    {
      "productId": "product_id_here",
      "quantity": 2
    }
  ],
  "total": 199.98,
  "shippingAddress": {
    "name": "John Doe",
    "email": "john@example.com",
    "address": "123 Main St",
    "city": "New York",
    "state": "NY",
    "zipcode": "10001",
    "country": "USA"
  },
  "paymentMethod": {
    "type": "credit-card"
  }
}
```
- **Response**: Created order object

### 5. Cancel Order
```
PATCH /api/orders/:id/cancel
```
- **Auth**: Required (User - own orders only)
- **Response**: Updated order with cancelled status
- **Note**: Cannot cancel if already shipped or delivered

### 6. Update Order Status (Admin Only) ✅ NOW WORKING
```
PATCH /api/orders/:id/status
```
- **Auth**: Required (Admin)
- **Body**:
```json
{
  "status": "processing"
}
```
- **Valid statuses**: pending, processing, shipped, delivered, cancelled
- **Response**: Updated order object
- **Frontend**: Available in Admin Orders View (status update buttons)

---

## Auth API

### 1. Signup
```
POST /api/auth/signup
```
- **Body**:
```json
{
  "email": "user@example.com",
  "username": "username",
  "password": "password123"
}
```
- **Response**: User object with JWT token

### 2. Login
```
POST /api/auth/login
```
- **Body**:
```json
{
  "email": "user@example.com",
  "password": "password123"
}
```
- **Response**: User object with JWT token and role

---

## Wishlist API

### 1. Get Wishlist
```
GET /api/wishlist
```
- **Auth**: Required (User)
- **Response**: Array of product IDs in wishlist

### 2. Add to Wishlist
```
POST /api/wishlist/:productId
```
- **Auth**: Required (User)
- **Response**: Updated wishlist

### 3. Remove from Wishlist
```
DELETE /api/wishlist/:productId
```
- **Auth**: Required (User)
- **Response**: Updated wishlist

---

## Testing Endpoints

### Using cURL

**Login as Admin:**
```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"admin123"}'
```

**Update Product:**
```bash
curl -X PUT http://localhost:5000/api/products/PRODUCT_ID \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"name":"Updated Product Name","price":149.99}'
```

**Delete Product:**
```bash
curl -X DELETE http://localhost:5000/api/products/PRODUCT_ID \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Update Order Status:**
```bash
curl -X PATCH http://localhost:5000/api/orders/ORDER_ID/status \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"status":"shipped"}'
```

### Using Frontend

All three endpoints are now integrated into the admin interface:

1. **Update Product**: 
   - Go to Admin Products View (`/admin/products`)
   - Click the Edit icon (pencil) on any product
   - Modify fields in the modal
   - Click "Update Product"

2. **Delete Product**:
   - Go to Admin Products View (`/admin/products`)
   - Click the Delete icon (trash) on any product
   - Confirm deletion in the alert
   - Product is removed from database

3. **Update Order Status**:
   - Go to Admin Orders View (`/admin/orders`)
   - Click on any order to expand details
   - Click one of the status buttons (Pending, Processing, Shipped, Delivered, Cancelled)
   - Order status updates with loading indicator

---

## Error Responses

All endpoints return errors in this format:
```json
{
  "message": "Error description",
  "error": "Detailed error message"
}
```

Common HTTP status codes:
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden (not admin)
- `404` - Not Found
- `500` - Server Error

---

## Admin Access

To use admin-only endpoints:

1. Create admin user:
```bash
cd server
node scripts/createAdmin.js admin@example.com admin admin123
```

2. Login to get token:
```bash
POST /api/auth/login
{
  "email": "admin@example.com",
  "password": "admin123"
}
```

3. Use the returned token in Authorization header for all admin requests

---

## Notes

- All product categories are dynamic (any string accepted)
- Order status can only be updated by admins
- Users can only cancel their own orders (before shipping)
- Email notifications are sent for order creation, cancellation, and status updates
- Product images should be valid URLs
- Prices should be positive numbers
- Ratings should be between 0 and 5

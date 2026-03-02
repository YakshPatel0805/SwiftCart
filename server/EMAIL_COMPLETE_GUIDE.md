# SwiftCart Email Notification System - Complete Guide

## Overview
SwiftCart has a comprehensive email notification system that keeps both customers and admins informed about order activities in real-time using Nodemailer.

## Table of Contents
1. [Email Types & Flow](#email-types--flow)
2. [Setup Instructions](#setup-instructions)
3. [Configuration](#configuration)
4. [testing](#test-email)
---

## Email Types & Flow

### Email Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    ORDER PLACEMENT                          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                    Customer Places Order
                            │
                            ├──────────────────────────────────┐
                            │                                  │
                            ▼                                  ▼
                    ┌───────────────┐                 ┌───────────────┐
                    │   CUSTOMER    │                 │     ADMIN     │
                    │   RECEIVES:   │                 │   RECEIVES:   │
                    ├───────────────┤                 ├───────────────┤
                    │ 1. Order      │                 │ 1. New Order  │
                    │   Confirmation│                 │    Alert      │
                    │               │                 │               │
                    │ 2. Payment    │                 │ Contains:     │
                    │   Confirmation│                 │ - Order ID    │
                    │    (if paid)  │                 │ - Customer    │
                    │               │                 │ - Items       │
                    └───────────────┘                 │ - Address     │
                                                      │ - Actions     │
                                                      └───────────────┘

┌─────────────────────────────────────────────────────────────┐
│                   ORDER CANCELLATION                        │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                   Customer Cancels Order
                            │
                            ├──────────────────────────────────┐
                            │                                  │
                            ▼                                  ▼
                    ┌───────────────┐                 ┌───────────────┐
                    │   CUSTOMER    │                 │     ADMIN     │
                    │   RECEIVES:   │                 │   RECEIVES:   │
                    ├───────────────┤                 ├───────────────┤
                    │1. Cancellation│                 │1. Cancellation│
                    |   Confirmation│                 │    Alert      │
                    │               │                 │               │
                    │ 2.Refund Info │                 │ Contains:     │
                    │    (5-7 days) │                 │ - Order ID    │
                    │               │                 │ - Customer    │
                    └───────────────┘                 │ - Refund Info │
                                                      │ - Actions     │
                                                      └───────────────┘
```

### All Email Types

#### 1. Order Confirmation (Customer)
- **Trigger**: Order placed
- **Recipient**: Customer email
- **Subject**: Order Confirmation - Order #[ID]
- **Color Theme**: Blue
- **Icon**: ✓
- **Contains**:
  - Order ID and date
  - Complete items list with quantities and prices
  - Shipping address
  - Total amount
  - Payment method
  - Order tracking information

#### 2. Payment Confirmation (Customer)
- **Trigger**: Payment processed
- **Recipient**: Customer email
- **Subject**: Payment Confirmed - Order #[ID]
- **Color Theme**: Green
- **Icon**: ✓
- **Contains**:
  - Payment amount
  - Payment method
  - Payment date
  - Order tracking info
  - Payment status
- **Note**: Only sent for Credit Card & Google Pay (not Cash on Delivery)

#### 3. Order Cancellation (Customer)
- **Trigger**: Order cancelled by customer
- **Recipient**: Customer email
- **Subject**: Order Cancelled - Order #[ID]
- **Color Theme**: Red
- **Icon**: ✗
- **Contains**:
  - Cancellation confirmation
  - Order details
  - Refund timeline (5-7 business days)
  - Customer support contact

#### 4. New Order Alert (Admin)
- **Trigger**: Customer places order
- **Recipient**: Admin email (ADMIN_EMAIL)
- **Subject**: 🔔 New Order Received - Order #[ID]
- **Color Theme**: Purple
- **Icon**: 🔔
- **Contains**:
  - Complete order details
  - Customer name & email
  - Items ordered with quantities
  - Shipping address with phone
  - Payment method
  - Order status
  - Action checklist for processing

#### 5. Cancellation Alert (Admin)
- **Trigger**: Customer cancels order
- **Recipient**: Admin email (ADMIN_EMAIL)
- **Subject**: ⚠️ Order Cancelled - Order #[ID]
- **Color Theme**: Red
- **Icon**: ⚠️
- **Contains**:
  - Cancellation details
  - Customer information
  - Order total
  - Refund requirements
  - Action checklist for handling

### Email Statistics

| Email Type | Recipient | Trigger | Frequency |
|------------|-----------|---------|-----------|
| Order Confirmation | Customer | Order placed | Per order |
| Payment Confirmation | Customer | Payment processed | Per paid order |
| Order Cancellation | Customer | Order cancelled | Per cancellation |
| New Order Alert | Admin | Order placed | Per order |
| Cancellation Alert | Admin | Order cancelled | Per cancellation |

---

## Setup Instructions

### Option 1: Gmail (Recommended for Development)

#### Step 1: Enable 2-Step Verification
1. Go to https://myaccount.google.com/security
2. Click on "2-Step Verification"
3. Follow the prompts to enable it (you'll need your phone)
4. Complete the setup

#### Step 2: Generate App Password
1. Go to https://myaccount.google.com/apppasswords
   - Or: Google Account → Security → 2-Step Verification → App passwords
2. You may need to sign in again
3. Select app: Choose "Mail"
4. Select device: Choose "Other (Custom name)"
5. Enter name: "SwiftCart" or "Ecommerce App"
6. Click "Generate"
7. **Copy the 16-character password** (shown in yellow box)
   - Example: `abcd efgh ijkl mnop`
   - Remove spaces when copying to .env

#### Step 3: Update .env File
Open `server/.env` and add:

```env
# Email Configuration
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=abcdefghijklmnop

# Admin Email (receives order notifications)
ADMIN_EMAIL=admin@swiftcart.com
```

Check your inbox for the test email.

## Configuration

### Environment Variables

```env
# MongoDB
MONGODB_URI=mongodb://localhost:27017/ecommerce

# JWT
JWT_SECRET=your_jwt_secret_key_change_this_in_production_12345

# Server
PORT=5000

# Email Configuration
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-16-character-app-password

# Admin Notifications
ADMIN_EMAIL=admin@swiftcart.com
```

## Testing

### Quick Start Testing

```bash
# 1. Setup email configuration
cd server
nano .env  # Add EMAIL_USER, EMAIL_PASSWORD, ADMIN_EMAIL

# 2. Test email setup
npm run test-email

# 3. Restart server
npm run dev

# 4. Test through application
```

### Testing Checklist

- [ ] Configure EMAIL_USER and EMAIL_PASSWORD
- [ ] Configure ADMIN_EMAIL
- [ ] Run `npm run test-email`
- [ ] Place a test order
- [ ] Verify customer receives order confirmation
- [ ] Verify customer receives payment confirmation (if paid)
- [ ] Verify admin receives new order alert
- [ ] Cancel a test order
- [ ] Verify customer receives cancellation email
- [ ] Verify admin receives cancellation alert
- [ ] Check spam/junk folders
- [ ] Verify all email content is correct

### Test Scenarios

#### 1. Test Order Confirmation
1. Place a new order through the checkout process
2. Check the email address provided in shipping details
3. Verify order confirmation email is received
4. Check email contains all order details

#### 2. Test Payment Confirmation
1. Place an order using Credit Card or Google Pay
2. Check for payment confirmation email
3. Verify payment details are correct
4. Note: Cash on Delivery does not send payment confirmation

#### 3. Test Order Cancellation
1. Go to Orders page
2. Cancel an order that is not shipped/delivered
3. Check customer email for cancellation confirmation
4. Check admin email for cancellation alert

#### 4. Test Admin Notifications
1. Place a new order
2. Check admin email for new order alert
3. Verify all order details are present
4. Cancel an order
5. Check admin email for cancellation alert

---

### Admin Not Receiving Emails
1. Verify ADMIN_EMAIL is set in .env
2. Check it's a valid email address
3. Check spam folder
4. Try using same email as EMAIL_USER for testing
5. Review server console logs

### Emails Going to Spam
- Add sender to contacts
- Mark as "Not Spam"
- For production, use dedicated email service
- Set up SPF and DKIM records
- Use verified domain
- Avoid spam trigger words

### Emails Look Broken
1. Check email client (use Gmail/Outlook)
2. Enable HTML emails in settings
3. Check internet connection
4. Try different email client
5. Verify HTML template syntax

## Summary

The SwiftCart email notification system provides:

- **5 email types** covering all order activities
- **Customer notifications** for order tracking and updates
- **Admin notifications** for real-time order management
- **Easy configuration** via environment variables


### Key Benefits

**For Customers:**
- Instant order confirmations
- Payment receipts
- Cancellation confirmations
- Professional communication

**For Admin:**
- Real-time order alerts
- Quick order processing
- Cancellation notifications
- Better customer service

**For Business:**
- Automated workflows
- Reduced manual work
- Better tracking
- Professional image

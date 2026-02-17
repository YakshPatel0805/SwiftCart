# Admin Guide

## Creating an Admin Account

### Step 1: Install Backend Dependencies

```bash
cd server
npm install
```

### Step 2: Setup Environment

Create `server/.env` file:
```env
MONGODB_URI=mongodb://localhost:27017/ecommerce
JWT_SECRET=your_secret_key_here_change_this
PORT=5000
```

### Step 3: Create Admin User

```bash
cd server
npm run create-admin
```

This creates an admin with default credentials:
- Email: admin@example.com
- Username: admin
- Password: admin123

Or create with custom credentials:
```bash
npm run create-admin your@email.com yourusername yourpassword
```

### Step 4: Start the Server

```bash
npm run dev
```

## Using the Admin Panel

### 1. Login as Admin

- Go to http://localhost:5173
- Click "Login"
- Enter admin credentials
- You'll see "Admin Panel" in the user menu

### 2. Upload Products via CSV

#### Option A: Use Example File
- Navigate to Admin Panel
- Upload `server/example_products.csv`

#### Option B: Create Your Own CSV

Download the template from Admin Panel or create a CSV with these columns:

**Required:**
- name
- price
- image (URL)
- category (clothing, electronics, or furniture)
- description

**Optional:**
- rating (0-5)
- reviews (number)
- inStock (true/false)

#### Example CSV:
```csv
name,price,image,category,description,rating,reviews,inStock
Summer Dress,79.99,https://example.com/dress.jpg,clothing,Beautiful summer dress,4.5,50,true
Bluetooth Speaker,149.99,https://example.com/speaker.jpg,electronics,Portable speaker,4.7,120,true
Coffee Table,299.99,https://example.com/table.jpg,furniture,Modern coffee table,4.3,35,true
```

### 3. Upload Process

1. Click "Select CSV File" in Admin Panel
2. Choose your CSV file
3. Click "Upload Products"
4. Review the results:
   - Success message shows number of products added
   - Any errors or warnings are displayed
   - Products appear immediately on the site

## Admin Capabilities

### What Admins Can Do:
- Upload multiple products via CSV
- Add individual products via API
- Edit existing products
- Delete products
- View all orders
- All regular user features

### What Regular Users Cannot Do:
- Access Admin Panel
- Upload or modify products
- Delete products
- Access admin-only API endpoints

## API Endpoints for Admins

All admin endpoints require JWT token with admin role:

```bash
# Add single product
POST /api/products
Headers: Authorization: Bearer <token>
Body: { name, price, image, category, description, ... }

# Upload CSV
POST /api/products/upload-csv
Headers: Authorization: Bearer <token>
Body: FormData with 'file' field

# Update product
PUT /api/products/:id
Headers: Authorization: Bearer <token>
Body: { fields to update }

# Delete product
DELETE /api/products/:id
Headers: Authorization: Bearer <token>
```

## Troubleshooting

### "Access denied. Admin only"
- Ensure you're logged in with admin account
- Check that user role is 'admin' in database
- Verify JWT token is being sent in requests

### CSV Upload Fails
- Check CSV format matches template
- Ensure category is one of: clothing, electronics, furniture
- Verify all required fields are present
- Check for special characters or encoding issues

### Products Not Appearing
- Refresh the page
- Check browser console for errors
- Verify MongoDB connection
- Check server logs for errors

## Security Notes

- Change default admin password immediately
- Use strong JWT_SECRET in production
- Keep admin credentials secure
- Regularly backup your database
- Use HTTPS in production

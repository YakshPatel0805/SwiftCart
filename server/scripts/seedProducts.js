import mongoose from 'mongoose';
import dotenv from 'dotenv';
import Product from '../models/Product.js';

dotenv.config();

const products = [
  {
    name: 'Premium Cotton T-Shirt',
    price: 29.99,
    image: 'https://images.pexels.com/photos/1021693/pexels-photo-1021693.jpeg?auto=compress&cs=tinysrgb&w=500',
    category: 'clothing',
    description: 'Comfortable and stylish cotton t-shirt perfect for everyday wear.',
    rating: 4.5,
    reviews: 128,
    inStock: true,
  },
  {
    name: 'Designer Jeans',
    price: 89.99,
    image: 'https://images.pexels.com/photos/1598507/pexels-photo-1598507.jpeg?auto=compress&cs=tinysrgb&w=500',
    category: 'clothing',
    description: 'High-quality denim jeans with a perfect fit and modern design.',
    rating: 4.7,
    reviews: 89,
    inStock: true,
  },
  {
    name: 'Elegant Dress',
    price: 149.99,
    image: 'https://images.pexels.com/photos/1536619/pexels-photo-1536619.jpeg?auto=compress&cs=tinysrgb&w=500',
    category: 'clothing',
    description: 'Beautiful and elegant dress suitable for special occasions.',
    rating: 4.8,
    reviews: 67,
    inStock: true,
  },
  {
    name: 'Casual Hoodie',
    price: 59.99,
    image: 'https://images.pexels.com/photos/994517/pexels-photo-994517.jpeg?auto=compress&cs=tinysrgb&w=500',
    category: 'clothing',
    description: 'Cozy and comfortable hoodie perfect for casual outings.',
    rating: 4.3,
    reviews: 156,
    inStock: true,
  },
  {
    name: 'Wireless Bluetooth Headphones',
    price: 199.99,
    image: 'https://images.pexels.com/photos/3394650/pexels-photo-3394650.jpeg?auto=compress&cs=tinysrgb&w=500',
    category: 'electronics',
    description: 'High-quality wireless headphones with excellent sound quality.',
    rating: 4.6,
    reviews: 234,
    inStock: true,
  },
  {
    name: 'Smart Watch',
    price: 299.99,
    image: 'https://images.pexels.com/photos/437037/pexels-photo-437037.jpeg?auto=compress&cs=tinysrgb&w=500',
    category: 'electronics',
    description: 'Advanced smartwatch with health tracking and notification features.',
    rating: 4.4,
    reviews: 178,
    inStock: true,
  },
  {
    name: 'Laptop Computer',
    price: 999.99,
    image: 'https://images.pexels.com/photos/18105/pexels-photo.jpg?auto=compress&cs=tinysrgb&w=500',
    category: 'electronics',
    description: 'Powerful laptop computer perfect for work and entertainment.',
    rating: 4.7,
    reviews: 145,
    inStock: true,
  },
  {
    name: 'Smartphone',
    price: 699.99,
    image: 'https://images.pexels.com/photos/607812/pexels-photo-607812.jpeg?auto=compress&cs=tinysrgb&w=500',
    category: 'electronics',
    description: 'Latest smartphone with advanced camera and processing power.',
    rating: 4.5,
    reviews: 312,
    inStock: true,
  },
  {
    name: 'Modern Sofa',
    price: 899.99,
    image: 'https://images.pexels.com/photos/2747449/pexels-photo-2747449.jpeg?auto=compress&cs=tinysrgb&w=500',
    category: 'furniture',
    description: 'Comfortable and stylish modern sofa perfect for your living room.',
    rating: 4.6,
    reviews: 89,
    inStock: true,
  },
  {
    name: 'Office Chair',
    price: 249.99,
    image: 'https://images.pexels.com/photos/1350789/pexels-photo-1350789.jpeg?auto=compress&cs=tinysrgb&w=500',
    category: 'furniture',
    description: 'Ergonomic office chair designed for comfort and productivity.',
    rating: 4.3,
    reviews: 156,
    inStock: true,
  },
  {
    name: 'Dining Table',
    price: 599.99,
    image: 'https://images.pexels.com/photos/1395967/pexels-photo-1395967.jpeg?auto=compress&cs=tinysrgb&w=500',
    category: 'furniture',
    description: 'Beautiful wooden dining table perfect for family meals.',
    rating: 4.7,
    reviews: 78,
    inStock: true,
  },
  {
    name: 'Bookshelf',
    price: 179.99,
    image: 'https://images.pexels.com/photos/1090638/pexels-photo-1090638.jpeg?auto=compress&cs=tinysrgb&w=500',
    category: 'furniture',
    description: 'Spacious bookshelf perfect for organizing your books and decor.',
    rating: 4.4,
    reviews: 92,
    inStock: true,
  },
];

async function seedProducts() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('Connected to MongoDB');

    await Product.deleteMany({});
    console.log('Cleared existing products');

    await Product.insertMany(products);
    console.log('Products seeded successfully');

    mongoose.connection.close();
  } catch (error) {
    console.error('Error seeding products:', error);
    process.exit(1);
  }
}

seedProducts();

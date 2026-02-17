// import React from 'react';
import { useState, useEffect } from 'react';
import { ShoppingBag, Truck, Shield, HeartHandshake } from 'lucide-react';
import { productsAPI } from '../services/api';
import { Product } from '../types';
// import ProductCard from '../components/Product/ProductCard';

interface HomeProps {
  onPageChange: (page: string) => void;
}

export default function Home({ onPageChange }: HomeProps) {
  const [products, setProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadProducts();
  }, []);

  const loadProducts = async () => {
    try {
      const data = await productsAPI.getAll();
      const normalizedData = data.map((p: any) => ({
        ...p,
        id: p._id || p.id
      }));
      setProducts(normalizedData);
    } catch (error) {
      console.error('Error loading products:', error);
    } finally {
      setLoading(false);
    }
  };

  // const featuredProducts = products.slice(0, 8);

  const features = [
    {
      icon: ShoppingBag,
      title: 'Quality Products',
      description: 'Carefully curated selection of high-quality items',
    },
    {
      icon: Truck,
      title: 'Free Shipping',
      description: 'Free shipping on orders over $50',
    },
    {
      icon: Shield,
      title: 'Secure Payment',
      description: '100% secure payment processing',
    },
    {
      icon: HeartHandshake,
      title: '24/7 Support',
      description: 'Customer support available around the clock',
    },
  ];

  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="relative bg-gradient-to-r from-blue-600 to-blue-800 text-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
          <div className="text-center">
            <h1 className="text-4xl md:text-6xl font-bold mb-6">
              Welcome to SwiftCart
            </h1>
            <p className="text-xl md:text-2xl mb-8 text-blue-100">
              Discover amazing products across clothing, electronics, and many more...
            </p>
            <button
              onClick={() => onPageChange('clothing')}
              className="bg-white text-blue-600 px-8 py-3 rounded-lg text-lg font-semibold hover:bg-gray-100 transition-colors"
            >
              Shop Now
            </button>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-16 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature, index) => (
              <div key={index} className="text-center">
                <div className="bg-blue-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                  <feature.icon className="h-8 w-8 text-blue-600" />
                </div>
                <h3 className="text-lg font-semibold text-gray-800 mb-2">
                  {feature.title}
                </h3>
                <p className="text-gray-600">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Categories Section */}
      <section className="py-16 overflow-hidden">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <h2 className="text-3xl font-bold text-center text-gray-800 mb-12">
            Shop by Category
          </h2>
          <div className="relative">
            <div className="flex gap-8 animate-scroll">
              {/* First set of categories */}
              <div
                onClick={() => onPageChange('clothing')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/1536619/pexels-photo-1536619.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Clothing"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Clothing</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('electronics')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/18105/pexels-photo.jpg?auto=compress&cs=tinysrgb&w=800"
                  alt="Electronics"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Electronics</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('furniture')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/1350789/pexels-photo-1350789.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Furniture"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Furniture</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('appliances')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/4686822/pexels-photo-4686822.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Appliances"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Appliances</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('beauty')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Beauty"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Beauty</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('accessories')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/1927259/pexels-photo-1927259.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Accessories"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Accessories</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('stationery')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/6373305/pexels-photo-6373305.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Stationery"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Stationery</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('books')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/1370295/pexels-photo-1370295.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Books"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Books</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('sports')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/3764011/pexels-photo-3764011.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Sports"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Sports</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('baby')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/1648375/pexels-photo-1648375.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Baby"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Baby</h3>
                </div>
              </div>

              {/* Duplicate all categories for seamless infinite loop */}
              <div
                onClick={() => onPageChange('clothing')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/1536619/pexels-photo-1536619.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Clothing"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Clothing</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('electronics')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/18105/pexels-photo.jpg?auto=compress&cs=tinysrgb&w=800"
                  alt="Electronics"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Electronics</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('furniture')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/1350789/pexels-photo-1350789.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Furniture"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Furniture</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('appliances')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/4686822/pexels-photo-4686822.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Appliances"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Appliances</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('beauty')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/3373736/pexels-photo-3373736.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Beauty"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Beauty</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('accessories')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/1927259/pexels-photo-1927259.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Accessories"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Accessories</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('stationery')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/6373305/pexels-photo-6373305.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Stationery"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Stationery</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('books')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/1370295/pexels-photo-1370295.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Books"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Books</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('sports')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/3764011/pexels-photo-3764011.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Sports"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Sports</h3>
                </div>
              </div>

              <div
                onClick={() => onPageChange('baby')}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src="https://images.pexels.com/photos/1648375/pexels-photo-1648375.jpeg?auto=compress&cs=tinysrgb&w=800"
                  alt="Baby"
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold">Baby</h3>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>


      <div className="text-center mb-10">
        <button
          onClick={() => onPageChange('all-products')}
          className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors"
        >
          View All Products
        </button>
      </div>
    </div>
  );
}
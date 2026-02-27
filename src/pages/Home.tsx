import { useNavigate } from 'react-router-dom';
import { ShoppingBag, Truck, Shield, HeartHandshake } from 'lucide-react';
import React, { useEffect, useState } from 'react';

interface Product {
  _id: string;
  image: string;
  category: string;
}

export default function Home() {
  const navigate = useNavigate();
  const [categoryProducts, setCategoryProducts] = useState<Product[]>([]);

  const features = [
    { icon: ShoppingBag, title: 'Quality Products', description: 'Carefully curated selection of high-quality items' },
    { icon: Truck, title: 'Free Shipping', description: 'Free shipping on orders over $50' },
    { icon: Shield, title: 'Secure Payment', description: '100% secure payment processing' },
    { icon: HeartHandshake, title: '24/7 Support', description: 'Customer support available around the clock' },
  ];

  useEffect(() => {
    const fetchProducts = async () => {
      try {
        const res = await fetch('http://localhost:5000/api/products');
        const data: Product[] = await res.json();

        const uniqueCategoryMap = new Map<string, Product>();
        data.forEach((product) => {
          if (!uniqueCategoryMap.has(product.category)) {
            uniqueCategoryMap.set(product.category, product);
          }
        });

        setCategoryProducts(Array.from(uniqueCategoryMap.values()));
      } catch (err) {
        console.error('Failed to fetch products', err);
      }
    };

    fetchProducts();
  }, []);

  return (
    <div>
      {/* Hero Section */}
      <section className="relative bg-gradient-to-r from-blue-600 to-blue-800 text-white">
        <div className="mx-auto px-4 sm:px-6 lg:px-8 py-20 text-center">
          <h1 className="text-4xl md:text-6xl font-bold mb-6">Welcome to SwiftCart</h1>
          <p className="text-xl md:text-2xl mb-8 text-blue-100">
            Discover amazing products across clothing, electronics, and many more...
          </p>
          <button
            onClick={() => navigate('/category/furniture')}
            className="bg-white text-blue-600 px-8 py-3 rounded-lg text-lg font-semibold hover:bg-gray-100 transition-colors"
          >
            Shop Now
          </button>
        </div>
      </section>

      {/* Features */}
      <section className="py-16 bg-gray-50">
        <div className="max-w-7xl mx-auto px-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {features.map((feature, index) => (
            <div key={index} className="text-center">
              <div className="bg-blue-100 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                <feature.icon className="h-8 w-8 text-blue-600" />
              </div>
              <h3 className="text-lg font-semibold text-gray-800 mb-2">{feature.title}</h3>
              <p className="text-gray-600">{feature.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Categories from Products */}
      <section className="py-16 overflow-hidden">
        <div className="max-w-7xl mx-auto px-4">
          <h2 className="text-3xl font-bold text-center text-gray-800 mb-12">
            Shop by Category
          </h2>

          <div className="flex gap-8 animate-scroll hover:[animation-play-state:paused]">
            {[ ...categoryProducts].map((product, index) => (
              <div
                key={index}
                onClick={() => navigate(`/category/${product.category}`)}
                className="relative overflow-hidden rounded-lg cursor-pointer group flex-shrink-0 w-80"
              >
                <img
                  src={product.image}
                  alt={product.category}
                  className="w-full h-64 object-cover transition-transform group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-black bg-opacity-40 flex items-center justify-center">
                  <h3 className="text-white text-2xl font-bold capitalize">
                    {product.category}
                  </h3>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <div className="text-center mb-10">
        <button
          onClick={() => navigate('/category/all')}
          className="bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 transition-colors"
        >
          View All Products
        </button>
      </div>
    </div>
  );
}
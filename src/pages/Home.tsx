import { useNavigate } from 'react-router-dom';
import { ShoppingBag, Truck, Shield, HeartHandshake } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { productsAPI } from '../services/api';

interface Product {
  _id: string;
  image: string;
  category: string;
  name: string;
  price: number;
  rating: number;
  reviews: string;
  inStock: boolean;
  stockQuantity: number;
}

export default function Home() {
  const navigate = useNavigate();
  const { recentlyViewed, addToRecentlyViewed } = useAuth();
  const [categoryProducts, setCategoryProducts] = useState<Product[]>([]);
  const [recentlyViewedProducts, setRecentlyViewedProducts] = useState<Product[]>([]);

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

  useEffect(() => {
    const fetchRecentlyViewed = async () => {
      if (recentlyViewed.length > 0) {
        try {
          const products = await Promise.all(
            recentlyViewed.map(async (id) => {
              try {
                return await productsAPI.getById(id);
              } catch {
                return null;
              }
            })
          );
          setRecentlyViewedProducts(products.filter((p): p is Product => p !== null));
        } catch (err) {
          console.error('Failed to fetch recently viewed', err);
        }
      }
    };

    fetchRecentlyViewed();
  }, [recentlyViewed]);

  return (
    <div>
      {/* Hero Section */}
      <section className="relative bg-gradient-to-r from-blue-600 to-blue-800 dark:from-blue-900 dark:to-blue-950 text-white">
        <div className="mx-auto px-4 sm:px-6 lg:px-8 py-20 text-center">
          <h1 className="text-4xl md:text-6xl font-bold mb-6">Welcome to SwiftCart</h1>
          <p className="text-xl md:text-2xl mb-8 text-blue-100 dark:text-blue-200">
            Discover amazing products across clothing, electronics, and many more...
          </p>
          <button
            onClick={() => navigate('/category/all')}
            className="bg-white text-blue-600 dark:bg-gray-800 dark:text-blue-400 px-8 py-3 rounded-lg text-lg font-semibold hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
          >
            Shop Now
          </button>
        </div>
      </section>

      {/* Features */}
      <section className="py-16 bg-gray-50 dark:bg-gray-900">
        <div className="max-w-7xl mx-auto px-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {features.map((feature, index) => (
            <div key={index} className="text-center">
              <div className="bg-blue-100 dark:bg-blue-900/30 w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-4">
                <feature.icon className="h-8 w-8 text-blue-600 dark:text-blue-400" />
              </div>
              <h3 className="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-2">{feature.title}</h3>
              <p className="text-gray-600 dark:text-gray-400">{feature.description}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Categories from Products */}
      <section className="py-16 overflow-hidden bg-gray-50 dark:bg-gray-900">
        <div className="max-w-7xl mx-auto px-4">
          <h2 className="text-3xl font-bold text-center text-gray-800 dark:text-gray-200 mb-12">
            Shop by Category
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {categoryProducts.slice(0, 6).map((product, index) => (
              <div
                key={index}
                onClick={() => navigate(`/category/${product.category}`)}
                className="relative overflow-hidden rounded-xl cursor-pointer group h-64 shadow-md hover:shadow-xl transition-all duration-300"
              >
                <img
                  src={product.image}
                  alt={product.category}
                  className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-110"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/70 via-black/20 to-transparent flex items-end justify-center pb-8 transition-opacity group-hover:from-black/80">
                  <h3 className="text-white text-2xl font-bold capitalize tracking-wide transform transition-transform duration-300 group-hover:scale-105">
                    {product.category}
                  </h3>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Recently Viewed */}
      {recentlyViewedProducts.length > 0 && (
        <section className="py-16 bg-gray-50 dark:bg-gray-900">
          <div className="max-w-7xl mx-auto px-4">
            <h2 className="text-3xl font-bold text-center text-gray-800 dark:text-gray-200 mb-12">
              Recently Viewed
            </h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-6">
              {recentlyViewedProducts.map((product) => (
                <div
                  key={product._id}
                  onClick={() => {
                    addToRecentlyViewed(product._id);
                    navigate(`/product/${product._id}`);
                  }}
                  className="bg-white dark:bg-gray-800 rounded-lg shadow-md dark:shadow-gray-900/50 overflow-hidden cursor-pointer hover:shadow-lg dark:hover:shadow-gray-900/80 transition-shadow"
                >
                  <img
                    src={product.image}
                    alt={product.name}
                    className="w-full h-48 object-cover"
                  />
                  <div className="p-4">
                    <h3 className="text-lg font-semibold text-gray-800 dark:text-gray-200 mb-2 line-clamp-2">
                      {product.name}
                    </h3>
                    <p className="text-2xl font-bold text-blue-600 dark:text-blue-400 mb-2">
                      ${product.price.toFixed(2)}
                    </p>
                    <div className="flex items-center">
                      <span className="text-sm text-gray-600 dark:text-gray-400">
                        ({product.reviews} reviews)
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      <div className="text-center mb-10">
        <button
          onClick={() => navigate('/category/all')}
          className="bg-blue-600 dark:bg-blue-600 text-white px-6 py-3 rounded-lg hover:bg-blue-700 dark:hover:bg-blue-500 transition-colors"
        >
          View All Products
        </button>
      </div>
    </div>
  );
}
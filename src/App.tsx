import { useState } from 'react';
import { AuthProvider } from './context/AuthContext';
import { CartProvider } from './context/CartContext';
import Header from './components/Layout/Header';
import Footer from './components/Layout/Footer';
import Home from './pages/Home';
import Login from './pages/Auth/Login';
import Signup from './pages/Auth/Signup';
import Dashboard from './pages/Dashboard';
import Cart from './pages/Cart';
import Checkout from './pages/Checkout';
import Contact from './pages/Contact';
import ProductGrid from './components/Product/ProductGrid';
import { products } from './data/products';

function App() {
  const [currentPage, setCurrentPage] = useState('home');

  const renderPage = () => {
    switch (currentPage) {
      case 'home':
        return <Home onPageChange={setCurrentPage} />;
      case 'login':
        return <Login onPageChange={setCurrentPage} />;
      case 'signup':
        return <Signup onPageChange={setCurrentPage} />;
      case 'dashboard':
        return <Dashboard onPageChange={setCurrentPage} />;
      case 'cart':
        return <Cart onPageChange={setCurrentPage} />;
      case 'checkout':
        return <Checkout onPageChange={setCurrentPage} />;
      case 'contact':
        return <Contact />;
      case 'clothing':
        return (
          <ProductGrid
            products={products.filter(p => p.category === 'clothing')}
            title="Clothing"
          />
        );
      case 'electronics':
        return (
          <ProductGrid
            products={products.filter(p => p.category === 'electronics')}
            title="Electronics"
          />
        );
      case 'furniture':
        return (
          <ProductGrid
            products={products.filter(p => p.category === 'furniture')}
            title="Furniture"
          />
        );
      case 'profile':
        return (
          <div className="min-h-screen bg-gray-50 py-12">
            <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="bg-white rounded-lg shadow-md p-6">
                <h1 className="text-2xl font-bold text-gray-900 mb-4">Profile Settings</h1>
                <p className="text-gray-600">Profile management functionality would be implemented here.</p>
              </div>
            </div>
          </div>
        );
      case 'orders':
        return (
          <div className="min-h-screen bg-gray-50 py-12">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="bg-white rounded-lg shadow-md p-6">
                <h1 className="text-2xl font-bold text-gray-900 mb-4">My Orders</h1>
                <div className="text-center py-8">
                  <p className="text-gray-500">You haven't placed any orders yet.</p>
                  <button
                    onClick={() => setCurrentPage('home')}
                    className="mt-4 bg-blue-600 text-white px-6 py-2 rounded-lg hover:bg-blue-700 transition-colors"
                  >
                    Start Shopping
                  </button>
                </div>
              </div>
            </div>
          </div>
        );
      case 'about':
        return (
          <div className="min-h-screen bg-gray-50 py-12">
            <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="bg-white rounded-lg shadow-md p-8">
                <h1 className="text-3xl font-bold text-gray-900 mb-6">About SwiftCart</h1>
                <div className="prose prose-lg text-gray-600">
                  <p>
                    SwiftCart is your premier destination for quality products across clothing, electronics, and furniture. 
                    We are committed to providing exceptional customer service and a seamless shopping experience.
                  </p>
                  <p>
                    Founded with the mission to make online shopping simple, secure, and enjoyable, we carefully curate 
                    our product selection to ensure you get the best value for your money.
                  </p>
                </div>
              </div>
            </div>
          </div>
        );
      case 'help':
        return (
          <div className="min-h-screen bg-gray-50 py-12">
            <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="bg-white rounded-lg shadow-md p-8">
                <h1 className="text-3xl font-bold text-gray-900 mb-6">Help Center</h1>
                <div className="space-y-6">
                  <div>
                    <h2 className="text-xl font-semibold text-gray-900 mb-2">Frequently Asked Questions</h2>
                    <div className="space-y-4">
                      <div>
                        <h3 className="font-medium text-gray-900">How do I track my order?</h3>
                        <p className="text-gray-600">You can track your order by visiting the "My Orders" section in your dashboard.</p>
                      </div>
                      <div>
                        <h3 className="font-medium text-gray-900">What is your return policy?</h3>
                        <p className="text-gray-600">We offer a 30-day return policy for most items. Please contact our support team for assistance.</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        );
      case 'privacy':
        return (
          <div className="min-h-screen bg-gray-50 py-12">
            <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="bg-white rounded-lg shadow-md p-8">
                <h1 className="text-3xl font-bold text-gray-900 mb-6">Privacy Policy</h1>
                <div className="prose text-gray-600">
                  <p>
                    This Privacy Policy describes how ShopAlpha collects, uses, and protects your information 
                    when you use our website and services.
                  </p>
                  <h2 className="text-xl font-semibold text-gray-900 mt-6 mb-3">Information We Collect</h2>
                  <p>
                    We collect information you provide directly to us, such as when you create an account, 
                    make a purchase, or contact us for support.
                  </p>
                </div>
              </div>
            </div>
          </div>
        );
      case 'terms':
        return (
          <div className="min-h-screen bg-gray-50 py-12">
            <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
              <div className="bg-white rounded-lg shadow-md p-8">
                <h1 className="text-3xl font-bold text-gray-900 mb-6">Terms of Service</h1>
                <div className="prose text-gray-600">
                  <p>
                    These Terms of Service govern your use of the ShopAlpha website and services.
                  </p>
                  <h2 className="text-xl font-semibold text-gray-900 mt-6 mb-3">Acceptance of Terms</h2>
                  <p>
                    By accessing and using our website, you accept and agree to be bound by the terms 
                    and provision of this agreement.
                  </p>
                </div>
              </div>
            </div>
          </div>
        );
      default:
        return <Home onPageChange={setCurrentPage} />;
    }
  };

  return (
    <AuthProvider>
      <CartProvider>
        <div className="min-h-screen bg-gray-50">
          <Header currentPage={currentPage} onPageChange={setCurrentPage} />
          <main>
            {renderPage()}
          </main>
          <Footer onPageChange={setCurrentPage} />
        </div>
      </CartProvider>
    </AuthProvider>
  );
}

export default App;
import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import { useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext';
import { CartProvider } from './context/CartContext';
import { WishlistProvider } from './context/WishlistContext';
import Header from './components/Layout/Header';
import AdminHeader from './components/Layout/AdminHeader';
import Footer from './components/Layout/Footer';
import Home from './pages/Home';
import Login from './pages/Auth/Login';
import Signup from './pages/Auth/Signup';
import Dashboard from './pages/Dashboard';
import Cart from './pages/Cart';
import Checkout from './pages/Checkout';
import Contact from './pages/Contact';
import AdminPanel from './pages/Admin/AdminPanel';
import AdminProductsView from './pages/AdminProductsView';
import AdminOrdersView from './pages/AdminOrdersView';
import Orders from './pages/Orders';
import CategoryPage from './pages/CategoryPage';
import SearchResults from './pages/SearchResults';
import Profile from './pages/Profile.tsx';
import About from './pages/About.tsx';
import Help from './pages/Help.tsx';
import Privacy from './pages/Privacy.tsx';
import Terms from './pages/Terms.tsx';
import Wishlist from './pages/Wishlist';

// Scroll to top on route change
function ScrollToTop() {
  const { pathname } = useLocation();

  useEffect(() => {
    window.scrollTo(0, 0);
  }, [pathname]);

  return null;
}

// Layout wrapper to conditionally render header based on user role
function AppLayout() {
  const { user } = useAuth();
  
  return (
    <div className="min-h-screen bg-gray-50">
      {user?.role === 'admin' ? <AdminHeader /> : <Header />}
      <main>
        <Routes>
          {/* Main Pages */}
          <Route path="/" element={<Home />} />
          <Route path="/login" element={<Login />} />
          <Route path="/signup" element={<Signup />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/cart" element={<Cart />} />
          <Route path="/checkout" element={<Checkout />} />
          <Route path="/contact" element={<Contact />} />
          <Route path="/orders" element={<Orders />} />
          <Route path="/profile" element={<Profile />} />
          <Route path="/wishlist" element={<Wishlist />} />
          
          {/* Admin */}
          <Route path="/admin" element={<AdminPanel />} />
          <Route path="/admin/products" element={<AdminProductsView />} />
          <Route path="/admin/orders" element={<AdminOrdersView />} />
          
          {/* Categories - Dynamic route */}
          <Route path="/category/:categoryName" element={<CategoryPage />} />
          
          {/* Search */}
          <Route path="/search" element={<SearchResults />} />
          
          {/* Info Pages */}
          <Route path="/about" element={<About />} />
          <Route path="/help" element={<Help />} />
          <Route path="/privacy" element={<Privacy />} />
          <Route path="/terms" element={<Terms />} />
        </Routes>
      </main>
      <Footer />
    </div>
  );
}

function App() {
  return (
    <AuthProvider>
      <WishlistProvider>
        <CartProvider>
          <Router>
            <ScrollToTop />
            <AppLayout />
          </Router>
        </CartProvider>
      </WishlistProvider>
    </AuthProvider>
  );
}

export default App;

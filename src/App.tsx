import { BrowserRouter as Router, Routes, Route, useLocation } from 'react-router-dom';
import { useEffect } from 'react';
import { AuthProvider } from './context/AuthContext';
import { CartProvider } from './context/CartContext';
import { WishlistProvider } from './context/WishlistContext';
import Header from './components/Layout/Header';
import Footer from './components/Layout/Footer';
import Home from './pages/Home';
import Login from './pages/Auth/Login';
import Signup from './pages/Auth/Signup';
import Dashboard from './pages/Dashboard';
import Cart from './pages/Cart';
import Checkout from './pages/Checkout';
import Contact from './pages/Contact';
import AdminPanel from './pages/Admin/AdminPanel';
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

function App() {
  return (
    <AuthProvider>
      <WishlistProvider>
        <CartProvider>
          <Router>
            <ScrollToTop />
            <div className="min-h-screen bg-gray-50">
              <Header />
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
                  
                  {/* Categories */}
                  <Route path="/category/clothing" element={<CategoryPage category="clothing" title="Clothing" />} />
                  <Route path="/category/electronics" element={<CategoryPage category="electronics" title="Electronics" />} />
                  <Route path="/category/furniture" element={<CategoryPage category="furniture" title="Furniture" />} />
                  <Route path="/category/appliances" element={<CategoryPage category="appliances" title="Appliances" />} />
                  <Route path="/category/beauty" element={<CategoryPage category="beauty" title="Beauty" />} />
                  <Route path="/category/accessories" element={<CategoryPage category="accessories" title="Accessories" />} />
                  <Route path="/category/stationery" element={<CategoryPage category="stationery" title="Stationery" />} />
                  <Route path="/category/books" element={<CategoryPage category="books" title="Books" />} />
                  <Route path="/category/sports" element={<CategoryPage category="sports" title="Sports" />} />
                  <Route path="/category/baby" element={<CategoryPage category="baby" title="Baby" />} />
                  <Route path="/category/all" element={<CategoryPage category="all" title="All Products" />} />
                  
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
          </Router>
        </CartProvider>
      </WishlistProvider>
    </AuthProvider>
  );
}

export default App;

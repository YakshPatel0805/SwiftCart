import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { productsAPI } from '../services/api';
import { Product } from '../types';
import ProductGrid from '../components/Product/ProductGrid';

export default function CategoryPage() {
  const { categoryName } = useParams<{ categoryName: string }>();
  const [products, setProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadProducts();
  }, [categoryName]);

  const loadProducts = async () => {
    try {
      setLoading(true);
      const data = await productsAPI.getAll();
      const normalizedData = data
        .map((p: any) => ({
          ...p,
          id: p._id || p.id
        }))
        .filter((p: Product) => categoryName === 'all' || p.category === categoryName);
      setProducts(normalizedData);
    } catch (error) {
      console.error('Error loading products:', error);
    } finally {
      setLoading(false);
    }
  };

  const getTitle = () => {
    if (categoryName === 'all') return 'All Products';
    return categoryName ? categoryName.charAt(0).toUpperCase() + categoryName.slice(1) : 'Products';
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center">Loading products...</div>
        </div>
      </div>
    );
  }

  return <ProductGrid products={products} title={getTitle()} />;
}

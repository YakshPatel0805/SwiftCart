import { useState, useEffect } from 'react';
import { productsAPI } from '../services/api';
import { Product } from '../types';
import ProductGrid from '../components/Product/ProductGrid';

interface CategoryPageProps {
  category: 'clothing' | 'electronics' | 'furniture' | 'appliances' | 'beauty' | 'accessories' | 'stationery' | 'books' | 'sports' | 'baby' | 'all';
  title: string;
}

export default function CategoryPage({ category, title }: CategoryPageProps) {
  const [products, setProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadProducts();
  }, [category]);

  const loadProducts = async () => {
    try {
      setLoading(true);
      const data = await productsAPI.getAll();
      const normalizedData = data
        .map((p: any) => ({
          ...p,
          id: p._id || p.id
        }))
        .filter((p: Product) => category === 'all' || p.category === category);
      setProducts(normalizedData);
    } catch (error) {
      console.error('Error loading products:', error);
    } finally {
      setLoading(false);
    }
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

  return <ProductGrid products={products} title={title} />;
}

import express from 'express';
import multer from 'multer';
import csv from 'csv-parser';
import { Readable } from 'stream';
import Product from '../models/Product.js';
import { authenticateToken } from '../middleware/auth.js';
import { isAdmin } from '../middleware/adminAuth.js';

const upload = multer({ storage: multer.memoryStorage() });
const router = express.Router();

router.get('/', async (req, res) => {
  try {
    const products = await Product.find();
    res.json(products);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.json(product);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

router.post('/', authenticateToken, isAdmin, async (req, res) => {
  try {
    const product = new Product(req.body);
    await product.save();
    res.status(201).json(product);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

router.post('/upload-csv', authenticateToken, isAdmin, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }

    const products = [];
    const errors = [];
    
    const stream = Readable.from(req.file.buffer.toString());
    
    stream
      .pipe(csv())
      .on('data', (row) => {
        try {
          const product = {
            name: row.name || row.Name,
            price: parseFloat(row.price || row.Price),
            image: row.image || row.Image,
            category: (row.category || row.Category).toLowerCase(),
            description: row.description || row.Description,
            rating: parseFloat(row.rating || row.Rating || 0),
            reviews: parseInt(row.reviews || row.Reviews || 0),
            inStock: (row.inStock || row.InStock || 'true').toLowerCase() === 'true'
          };

          if (!['clothing', 'electronics', 'furniture', 'appliances', 'beauty', 'accessories', 'stationery', 'books', 'sports', 'baby'].includes(product.category)) {
            errors.push(`Invalid category for product: ${product.name}`);
            return;
          }

          if (!product.name || !product.price || !product.image || !product.description) {
            errors.push(`Missing required fields for product: ${product.name || 'Unknown'}`);
            return;
          }

          products.push(product);
        } catch (error) {
          errors.push(`Error parsing row: ${error.message}`);
        }
      })
      .on('end', async () => {
        try {
          if (products.length === 0) {
            return res.status(400).json({ 
              message: 'No valid products found in CSV',
              errors 
            });
          }

          const savedProducts = await Product.insertMany(products);
          
          res.json({
            message: `Successfully uploaded ${savedProducts.length} products`,
            count: savedProducts.length,
            products: savedProducts,
            errors: errors.length > 0 ? errors : undefined
          });
        } catch (error) {
          res.status(500).json({ 
            message: 'Error saving products to database', 
            error: error.message 
          });
        }
      })
      .on('error', (error) => {
        res.status(500).json({ 
          message: 'Error parsing CSV file', 
          error: error.message 
        });
      });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

router.put('/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const product = await Product.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }
    
    res.json(product);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

router.delete('/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const product = await Product.findByIdAndDelete(req.params.id);
    
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }
    
    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

export default router;

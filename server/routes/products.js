import express from 'express';
import multer from 'multer';
import csv from 'csv-parser';
import { Readable } from 'stream';
import Product from '../models/Product.js';
import { authenticateToken } from '../middleware/auth.js';
import { isAdmin } from '../middleware/adminAuth.js';
import redisClient from '../utils/redis.js';

const upload = multer({ storage: multer.memoryStorage() });
const router = express.Router();

router.get('/categories', async (req, res) => {
  try {
    if (redisClient.isOpen) {
      const cachedCategories = await redisClient.get('categories');
      if (cachedCategories) {
        return res.json(JSON.parse(cachedCategories));
      }
    }

    const categories = await Product.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { _id: 1 } },
      { $project: { category: '$_id', count: 1, _id: 0 } }
    ]);

    if (redisClient.isOpen) {
      await redisClient.setEx('categories', 3600, JSON.stringify(categories));
    }

    res.json(categories);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

router.get('/', async (req, res) => {
  try {
    if (redisClient.isOpen) {
      const cachedProducts = await redisClient.get('products:all');
      if (cachedProducts) {
        return res.json(JSON.parse(cachedProducts));
      }
    }

    const products = await Product.find();

    if (redisClient.isOpen) {
      await redisClient.setEx('products:all', 3600, JSON.stringify(products));
    }

    res.json(products);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

router.get('/:id', async (req, res) => {
  try {
    if (redisClient.isOpen) {
      const cachedProduct = await redisClient.get(`product:${req.params.id}`);
      if (cachedProduct) {
        return res.json(JSON.parse(cachedProduct));
      }
    }

    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ message: 'Product not found' });
    }

    if (redisClient.isOpen) {
      await redisClient.setEx(`product:${req.params.id}`, 3600, JSON.stringify(product));
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

    if (redisClient.isOpen) {
      await redisClient.del(['products:all', 'categories']);
    }

    res.status(201).json(product);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

router.post(
  '/upload-csv',
  authenticateToken,
  isAdmin,
  upload.single('file'),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded' });
      }

      const products = [];
      const errors = [];

      const stream = Readable.from(req.file.buffer);

      stream
        .pipe(csv())
        .on('data', (row) => {
          try {
            const rawCategory = row.category || row.Category || '';

            const product = {
              name: row.name || row.Name,
              price: parseFloat(row.price || row.Price),
              image: row.image || row.Image,
              category: rawCategory.toLowerCase().trim(),
              description: row.description || row.Description,
              rating: parseFloat(row.rating || row.Rating || 0),
              reviews: row.reviews || row.Reviews || '',
              inStock: String(row.inStock || row.InStock || 'true').toLowerCase() === 'true',
              stockQuantity: Number(row.stockQuantity || row.StockQuantity || 0)
            };

            if (
              !product.name ||
              isNaN(product.price) ||
              !product.image ||
              !product.description ||
              !product.category
            ) {
              errors.push(`Missing/invalid fields for product: ${product.name || 'Unknown'}`);
              return;
            }

            products.push(product);
          } catch (err) {
            errors.push(`Row error: ${err.message}`);
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

            if (redisClient.isOpen) {
              await redisClient.del(['products:all', 'categories']);
            }

            res.json({
              message: `Successfully uploaded ${savedProducts.length} products`,
              count: savedProducts.length,
              products: savedProducts,
              errors: errors.length ? errors : undefined
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
  }
);

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

    if (redisClient.isOpen) {
      await redisClient.del(['products:all', 'categories', `product:${req.params.id}`]);
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

    if (redisClient.isOpen) {
      await redisClient.del(['products:all', 'categories', `product:${req.params.id}`]);
    }

    res.json({ message: 'Product deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

export default router;

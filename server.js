const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));

// Import models
const User = require('./backend/models/User');
const Car = require('./backend/models/Car');
const Booking = require('./backend/models/Booking');
const Payment = require('./backend/models/Payment');

// Auth Middleware
const auth = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');
        if (!token) return res.status(401).json({ message: 'No token' });

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.id).select('-password');
        if (!user) return res.status(401).json({ message: 'Invalid token' });

        req.user = user;
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token invalid' });
    }
};

// ===== AUTH ROUTES =====
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { name, email, password } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists with this email' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'Registration successful! You can now login.' });
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ message: 'Server error during registration' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { id: user._id, email: user.email }, 
            process.env.JWT_SECRET, 
            { expiresIn: "7d" }
        );

        res.status(200).json({ 
            message: 'Login successful!', 
            token, 
            user: { 
                id: user._id, 
                name: user.name, 
                email: user.email 
            } 
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ message: 'Server error during login' });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email });
        
        if (!user) {
            return res.status(404).json({ message: 'Email not found' });
        }

        const resetToken = crypto.randomBytes(20).toString('hex');
        user.resetToken = resetToken;
        user.resetTokenExpire = Date.now() + 10 * 60 * 1000;
        await user.save();

        res.status(200).json({ message: 'Password reset token generated', resetToken });
    } catch (err) {
        console.error('Forgot password error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { resetToken, newPassword } = req.body;

        const user = await User.findOne({
            resetToken,
            resetTokenExpire: { $gt: Date.now() }
        });

        if (!user) {
            return res.status(400).json({ message: 'Invalid or expired reset token' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpire = undefined;
        await user.save();

        res.status(200).json({ message: 'Password reset successful' });
    } catch (err) {
        console.error('Reset password error:', err);
        res.status(500).json({ message: 'Server error' });
    }
});

// ===== CAR ROUTES =====
app.get('/api/cars', async (req, res) => {
    try {
        const cars = await Car.find();
        res.json(cars);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching cars' });
    }
});

app.get('/api/cars/:id', async (req, res) => {
    try {
        const car = await Car.findById(req.params.id);
        if (!car) return res.status(404).json({ message: 'Car not found' });
        res.json(car);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching car' });
    }
});

// ===== BOOKING ROUTES =====
app.post('/api/bookings', auth, async (req, res) => {
    try {
        const { carId, startDate, endDate, pickupLocation } = req.body;
        
        const car = await Car.findById(carId);
        if (!car) return res.status(404).json({ message: 'Car not found' });

        const start = new Date(startDate);
        const end = new Date(endDate);
        const totalDays = Math.ceil((end - start) / (1000 * 60 * 60 * 24));
        const totalPrice = car.price * totalDays;

        const booking = new Booking({
            userId: req.user.id,
            carId,
            startDate: start,
            endDate: end,
            totalDays,
            totalPrice,
            pickupLocation
        });

        await booking.save();
        await booking.populate('carId');
        
        res.status(201).json({ message: 'Booking successful', booking });
    } catch (error) {
        res.status(500).json({ message: 'Error creating booking' });
    }
});

app.get('/api/bookings/my-bookings', auth, async (req, res) => {
    try {
        const bookings = await Booking.find({ userId: req.user.id })
            .populate('carId')
            .sort({ createdAt: -1 });
        res.json(bookings);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching bookings' });
    }
});

// ===== USER ROUTES =====
app.get('/api/users/profile', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching profile' });
    }
});

app.put('/api/users/profile', auth, async (req, res) => {
    try {
        const { name, phone, address, licenseNumber } = req.body;
        const user = await User.findByIdAndUpdate(
            req.user.id,
            { name, phone, address, licenseNumber },
            { new: true }
        ).select('-password');
        res.json({ message: 'Profile updated', user });
    } catch (error) {
        res.status(500).json({ message: 'Error updating profile' });
    }
});

// Serve frontend pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/home', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});

app.get('/cars', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'cars.html'));
});

app.get('/booking', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'booking.html'));
});

app.get('/profile', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/contact', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'contact.html'));
});

app.get('/payment', (req, res) => { 
    res.sendFile(path.join(__dirname, 'public', 'payment.html'));
});

// Payment routes
app.post('/api/payments/create-intent', auth, async (req, res) => {
    try {
        const { bookingId, amount } = req.body;
        
        const paymentIntent = {
            id: 'pi_' + Math.random().toString(36).substr(2, 9),
            client_secret: 'pi_' + Math.random().toString(36).substr(2, 24) + '_secret',
            amount: amount,
            currency: 'usd',
            status: 'requires_payment_method'
        };
        
        res.json({ 
            success: true, 
            clientSecret: paymentIntent.client_secret,
            paymentIntentId: paymentIntent.id
        });
        
    } catch (error) {
        console.error('Payment intent error:', error);
        res.status(500).json({ message: 'Error creating payment intent' });
    }
});

app.post('/api/payments/process', auth, async (req, res) => {
    try {
        const { 
            bookingId, 
            paymentMethod, 
            cardNumber, 
            expiryDate, 
            cvv, 
            cardholderName,
            amount 
        } = req.body;

        if (!cardNumber || !expiryDate || !cvv || !cardholderName) {
            return res.status(400).json({ message: 'All payment fields are required' });
        }

        const isPaymentSuccessful = Math.random() > 0.1;

        if (isPaymentSuccessful) {
            const booking = await Booking.findById(bookingId);
            if (!booking) {
                return res.status(404).json({ message: 'Booking not found' });
            }

            booking.status = 'Confirmed';
            booking.paymentStatus = 'Paid';
            booking.paymentMethod = paymentMethod;
            booking.paymentDate = new Date();
            booking.customerName = cardholderName;
            booking.customerEmail = req.user.email;
            booking.customerPhone = req.user.phone;
            await booking.save();

            const payment = new Payment({
                bookingId: bookingId,
                userId: req.user.id,
                amount: amount,
                paymentMethod: paymentMethod,
                paymentStatus: 'Completed',
                paymentIntentId: 'pi_' + Math.random().toString(36).substr(2, 9),
                transactionId: 'txn_' + Math.random().toString(36).substr(2, 9),
                customerEmail: req.user.email,
                customerName: cardholderName,
                cardLast4: cardNumber.slice(-4),
                cardBrand: getCardBrand(cardNumber),
                paidAt: new Date()
            });
            await payment.save();

            res.json({ 
                success: true, 
                message: 'Payment successful! Your booking is confirmed.',
                booking: booking,
                payment: payment
            });
        } else {
            res.status(400).json({ 
                success: false, 
                message: 'Payment failed. Please try again or use a different payment method.' 
            });
        }

    } catch (error) {
        console.error('Payment processing error:', error);
        res.status(500).json({ message: 'Error processing payment' });
    }
});

function getCardBrand(cardNumber) {
    const firstDigit = cardNumber[0];
    if (firstDigit === '4') return 'Visa';
    if (firstDigit === '5') return 'MasterCard';
    if (firstDigit === '3') return 'American Express';
    if (firstDigit === '6') return 'Discover';
    return 'Unknown';
}

app.get('/api/payments/history', auth, async (req, res) => {
    try {
        const payments = await Payment.find({ userId: req.user.id })
            .populate('bookingId')
            .sort({ createdAt: -1 });
        res.json(payments);
    } catch (error) {
        res.status(500).json({ message: 'Error fetching payment history' });
    }
});

// Connect to MongoDB
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('✅ MongoDB connected to Atlas');
        await addSampleCars();
    } catch (err) {
        console.error('❌ MongoDB connection error:', err.message);
        process.exit(1);
    }
};

const addSampleCars = async () => {
    try {
        const count = await Car.countDocuments();
        
        if (count === 0) {
            const cars = [
                { name: 'Toyota Corolla', price: 40, image: 'images/1.jpeg', type: 'Sedan', seats: 5, transmission: 'Automatic', fuel: 'Petrol' },
                { name: 'Mercedes Benz', price: 120, image: 'images/2.jpg', type: 'Luxury', seats: 5, transmission: 'Automatic', fuel: 'Petrol' },
                { name: 'Honda Civic', price: 55, image: 'images/3.jpg', type: 'Sedan', seats: 5, transmission: 'Automatic', fuel: 'Petrol' },
                { name: 'Ford Mustang', price: 85, image: 'images/4.jpeg', type: 'Sports', seats: 4, transmission: 'Manual', fuel: 'Petrol' },
                { name: 'Toyota RAV4', price: 65, image: 'images/5.jpeg', type: 'SUV', seats: 5, transmission: 'Automatic', fuel: 'Hybrid' },
                { name: 'BMW 3 Series', price: 95, image: 'images/6.jpeg', type: 'Luxury', seats: 5, transmission: 'Automatic', fuel: 'Petrol' }
            ];
            await Car.insertMany(cars);
            console.log('✅ Sample cars added to database');
        }
    } catch (error) {
        console.error('Error adding sample cars:', error);
    }
};

connectDB();

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Car Rental Server running on port ${PORT}`));
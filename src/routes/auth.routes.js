import express from 'express';
import { register, login, getAllUsers } from '../controllers/authen.controller.js';
import authenticate from '../middleware/authMiddleware.js';


const route = express.Router();

route.post('/register', register);
route.post('/login', login);
route.get('/users', authenticate, getAllUsers);

export default route;
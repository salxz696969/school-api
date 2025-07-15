import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import db from "../models/index.js";
const User = db.User;

const SECRET = process.env.JWT_SECRET || "IamJack21";

/**
 * @swagger
 * tags:
 *   - name: Auth
 *     description: User registration and login
 */

/**
 * @swagger
 * /auth/register:
 *   post:
 *     summary: Register a new user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, email, password]
 *             properties:
 *               name:
 *                 type: string
 *                 example: Ra Fat
 *               email:
 *                 type: string
 *                 example: RaFat@gmail.com
 *               password:
 *                 type: string
 *                 example: RaFat21
 *     responses:
 *       201:
 *         description: User registered successfully
 *       400:
 *         description: Email already exists
 */
export const register = async (req, res) => {
  const { name, email, password } = req.body;

  const exists = await User.findOne({ where: { email } });
  if (exists) {
    return res.status(400).json({ message: "Email already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await User.create({ name, email, password: hashedPassword });

  res.status(201).json({
    message: "User registered",
    user: { id: user.id, email: user.email }
  });
};

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login user and get JWT token
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [email, password]
 *             properties:
 *               email:
 *                 type: string
 *                 example: RaFat@gmail.com
 *               password:
 *                 type: string
 *                 example: RaFat21
 *     responses:
 *       200:
 *         description: Successful login
 *       401:
 *         description: Invalid credentials
 *       404:
 *         description: User not found
 */
export const login = async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ where: { email } });
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ message: "Invalid email or password" });

//   Generate JWT token to authenticate user and give expires in 1 hour
  const token = jwt.sign({ id: user.id, email: user.email }, SECRET, { expiresIn: "1h" });

  res.json({ token, user: { id: user.id, email: user.email } });
};

/**
 * @swagger
 * /auth/users:
 *   get:
 *     summary: Get all registered users (Protected)
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: List of users
 *       401:
 *         description: Unauthorized (Missing or invalid token)
 */
export const getAllUsers = async (req, res) => {
  const users = await User.findAll({ attributes: ['id', 'name', 'email'] });
  res.json(users);
};
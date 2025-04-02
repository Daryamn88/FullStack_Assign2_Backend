const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Employee = require('../models/Employee');
const { AuthenticationError, UserInputError } = require('apollo-server-express');

const resolvers = {
    Query: {
        login: async (_, { username, password }) => {
            try {
                // Input validation
                if (!username || !password) {
                    throw new UserInputError('Username and password are required');
                }

                const user = await User.findOne({ username });
                if (!user) {
                    throw new AuthenticationError('Invalid username or password');
                }

                const validPassword = await bcrypt.compare(password, user.password);
                if (!validPassword) {
                    throw new AuthenticationError('Invalid username or password');
                }

                // Include user ID in the token payload
                const token = jwt.sign(
                    { 
                        userId: user._id,
                        username: user.username 
                    }, 
                    process.env.JWT_SECRET, 
                    { expiresIn: '1h' }
                );

                // Return user data without password
                const userData = user.toObject();
                delete userData.password;

                return { 
                    token, 
                    user: userData,
                    tokenExpiration: 1
                };
            } catch (error) {
                console.error('Login error:', error);
                throw error;
            }
        },

        getAllEmployees: async () => {
            try {
                return await Employee.find().lean();
            } catch (error) {
                console.error('Error fetching employees:', error);
                throw new Error('Failed to fetch employees');
            }
        },

        getEmployeeById: async (_, { eid }) => {
            try {
                if (!eid) {
                    throw new UserInputError('Employee ID is required');
                }
                const employee = await Employee.findById(eid);
                if (!employee) {
                    throw new Error('Employee not found');
                }
                return employee;
            } catch (error) {
                console.error('Error fetching employee:', error);
                throw error;
            }
        },

        searchEmployeeByDesignationOrDepartment: async (_, { designation, department }) => {
            try {
                let filter = {};
                if (designation) filter.designation = designation;
                if (department) filter.department = department;
                
                if (Object.keys(filter).length === 0) {
                    throw new UserInputError('At least one search parameter is required');
                }
                
                return await Employee.find(filter).lean();
            } catch (error) {
                console.error('Search error:', error);
                throw error;
            }
        }
    },

    Mutation: {
        signup: async (_, { username, email, password }) => {
            try {
                // Input validation
                if (!username || !email || !password) {
                    throw new UserInputError('All fields are required');
                }

                // Check if user exists
                const existingUser = await User.findOne({ $or: [{ username }, { email }] });
                if (existingUser) {
                    throw new UserInputError('Username or email already exists');
                }

                // Hash password
                const hashedPassword = await bcrypt.hash(password, 12); // Increased salt rounds
                
                // Create user
                const user = new User({ 
                    username, 
                    email, 
                    password: hashedPassword 
                });

                await user.save();
                
                // Return user without password
                const userData = user.toObject();
                delete userData.password;
                return userData;
            } catch (error) {
                console.error('Signup error:', error);
                throw error;
            }
        },

        addEmployee: async (_, args) => {
            try {
                // Validate required fields
                if (!args.first_name || !args.last_name) {
                    throw new UserInputError('First name and last name are required');
                }

                const employee = new Employee(args);
                await employee.save();
                return employee;
            } catch (error) {
                console.error('Error adding employee:', error);
                throw error;
            }
        },

        updateEmployeeById: async (_, { eid, ...updates }) => {
            try {
                if (!eid) {
                    throw new UserInputError('Employee ID is required');
                }

                const updatedEmployee = await Employee.findByIdAndUpdate(
                    eid, 
                    updates, 
                    { new: true, runValidators: true }
                );

                if (!updatedEmployee) {
                    throw new Error('Employee not found');
                }

                return updatedEmployee;
            } catch (error) {
                console.error('Error updating employee:', error);
                throw error;
            }
        },

        deleteEmployeeById: async (_, { eid }) => {
            try {
                if (!eid) {
                    throw new UserInputError('Employee ID is required');
                }

                const deletedEmployee = await Employee.findByIdAndDelete(eid);
                if (!deletedEmployee) {
                    throw new Error('Employee not found');
                }

                return {
                    success: true,
                    message: "Employee deleted successfully",
                    id: eid
                };
            } catch (error) {
                console.error('Error deleting employee:', error);
                throw error;
            }
        }
    }
};

module.exports = resolvers;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const Employee = require('../models/Employee');
const { AuthenticationError } = require('apollo-server-express');

const resolvers = {
    Query: {
        login: async (_, { username, password }) => {
            const user = await User.findOne({ username });
            if (!user) throw new AuthenticationError('Invalid username or password');
            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) throw new AuthenticationError('Invalid username or password');

            const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
            return { token, user };
        },

        getAllEmployees: async () => await Employee.find(),

        getEmployeeById: async (_, { eid }) => await Employee.findById(eid),

        searchEmployeeByDesignationOrDepartment: async (_, { designation, department }) => {
            let filter = {};
            if (designation) filter.designation = designation;
            if (department) filter.department = department;
            return await Employee.find(filter);
        }
    },

    Mutation: {
        signup: async (_, { username, email, password }) => {
            const hashedPassword = await bcrypt.hash(password, 10);
            const user = new User({ username, email, password: hashedPassword });
            return await user.save();
        },

        addEmployee: async (_, args) => {
            const employee = new Employee(args);
            return await employee.save();
        },

        updateEmployeeById: async (_, { eid, ...updates }) => {
            const updatedEmployee = await Employee.findByIdAndUpdate(eid, updates, { new: true });
            return updatedEmployee;
        },

        deleteEmployeeById: async (_, { eid }) => {
            await Employee.findByIdAndDelete(eid);
            return "Employee deleted successfully.";
        }
    }
};

module.exports = resolvers;

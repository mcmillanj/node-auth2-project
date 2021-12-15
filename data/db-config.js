// DO NOT CHANGE THIS FILE
const knex = require('knex')
const configs = require('../knexfile.js')
 const environment = process.env.NODE_ENV || 'development'
// const { NODE_ENV } = require('./../secrets')
module.exports = knex(configs[environment])

const path = require('path');
const webpack = require('webpack');
const htmlWebpackPlugin = require('html-webpack-plugin');
const copyWebpackPlugin = require('copy-webpack-plugin');

module.exports = {
  entry: path.join(__dirname,'..','src','index.js'),
  output: {
    path: path.resolve(__dirname,'..','dist'),
    filename: 'main.js'
  },
  module: {
    rules: [{ 
      test: /\.jsx?$/,
      loader: 'babel-loader',
      exclude: path.resolve(__dirname,'..','node_modules'),
      query: {
        presets: ['env', 'react'],
        plugins: [
          "transform-class-properties",
          "transform-object-rest-spread"
        ]
      }
    },{
      test: /\.(png|jpe?g|svg|eot|ttf|woff|woff2|otf)$/,
      use: {
        loader: 'url-loader',
        options: {
          limit: 100000,
          fallback: 'file-loader'
        },
      },
    }]
  },
  plugins: [
    new htmlWebpackPlugin({
      template: path.resolve(__dirname,'..','src','index.html'),
      filename: 'index.html',
      inject: 'body'
    })
  ]
}
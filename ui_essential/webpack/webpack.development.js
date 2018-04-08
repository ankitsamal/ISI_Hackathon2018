const path = require('path');
const webpack = require('webpack');
const merge = require('webpack-merge');
const common = require('./webpack.common.js');

module.exports = merge(common, {
  devtool: 'inline-source-map',
  devServer: {
    historyApiFallback: true,
    compress: true,
    host: '0.0.0.0',
    port: 5000
  },
  module: {
    rules: [{
      test: /\.scss$/,
      use: [{
          loader: "style-loader"
        },{ 
          loader: "css-loader",
          options: {modules:true,localIdentName:'[local]_[hash:4]'}
        },{
          loader: "sass-loader"
      }]
    }]
  },
  plugins: [
    new webpack.DefinePlugin({
      'process.env.NODE_ENV': JSON.stringify('development')
    }),
  ]
});
function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
function _regeneratorRuntime() { "use strict"; /*! regenerator-runtime -- Copyright (c) 2014-present, Facebook, Inc. -- license (MIT): https://github.com/facebook/regenerator/blob/main/LICENSE */ _regeneratorRuntime = function _regeneratorRuntime() { return e; }; var t, e = {}, r = Object.prototype, n = r.hasOwnProperty, o = Object.defineProperty || function (t, e, r) { t[e] = r.value; }, i = "function" == typeof Symbol ? Symbol : {}, a = i.iterator || "@@iterator", c = i.asyncIterator || "@@asyncIterator", u = i.toStringTag || "@@toStringTag"; function define(t, e, r) { return Object.defineProperty(t, e, { value: r, enumerable: !0, configurable: !0, writable: !0 }), t[e]; } try { define({}, ""); } catch (t) { define = function define(t, e, r) { return t[e] = r; }; } function wrap(t, e, r, n) { var i = e && e.prototype instanceof Generator ? e : Generator, a = Object.create(i.prototype), c = new Context(n || []); return o(a, "_invoke", { value: makeInvokeMethod(t, r, c) }), a; } function tryCatch(t, e, r) { try { return { type: "normal", arg: t.call(e, r) }; } catch (t) { return { type: "throw", arg: t }; } } e.wrap = wrap; var h = "suspendedStart", l = "suspendedYield", f = "executing", s = "completed", y = {}; function Generator() {} function GeneratorFunction() {} function GeneratorFunctionPrototype() {} var p = {}; define(p, a, function () { return this; }); var d = Object.getPrototypeOf, v = d && d(d(values([]))); v && v !== r && n.call(v, a) && (p = v); var g = GeneratorFunctionPrototype.prototype = Generator.prototype = Object.create(p); function defineIteratorMethods(t) { ["next", "throw", "return"].forEach(function (e) { define(t, e, function (t) { return this._invoke(e, t); }); }); } function AsyncIterator(t, e) { function invoke(r, o, i, a) { var c = tryCatch(t[r], t, o); if ("throw" !== c.type) { var u = c.arg, h = u.value; return h && "object" == _typeof(h) && n.call(h, "__await") ? e.resolve(h.__await).then(function (t) { invoke("next", t, i, a); }, function (t) { invoke("throw", t, i, a); }) : e.resolve(h).then(function (t) { u.value = t, i(u); }, function (t) { return invoke("throw", t, i, a); }); } a(c.arg); } var r; o(this, "_invoke", { value: function value(t, n) { function callInvokeWithMethodAndArg() { return new e(function (e, r) { invoke(t, n, e, r); }); } return r = r ? r.then(callInvokeWithMethodAndArg, callInvokeWithMethodAndArg) : callInvokeWithMethodAndArg(); } }); } function makeInvokeMethod(e, r, n) { var o = h; return function (i, a) { if (o === f) throw Error("Generator is already running"); if (o === s) { if ("throw" === i) throw a; return { value: t, done: !0 }; } for (n.method = i, n.arg = a;;) { var c = n.delegate; if (c) { var u = maybeInvokeDelegate(c, n); if (u) { if (u === y) continue; return u; } } if ("next" === n.method) n.sent = n._sent = n.arg;else if ("throw" === n.method) { if (o === h) throw o = s, n.arg; n.dispatchException(n.arg); } else "return" === n.method && n.abrupt("return", n.arg); o = f; var p = tryCatch(e, r, n); if ("normal" === p.type) { if (o = n.done ? s : l, p.arg === y) continue; return { value: p.arg, done: n.done }; } "throw" === p.type && (o = s, n.method = "throw", n.arg = p.arg); } }; } function maybeInvokeDelegate(e, r) { var n = r.method, o = e.iterator[n]; if (o === t) return r.delegate = null, "throw" === n && e.iterator["return"] && (r.method = "return", r.arg = t, maybeInvokeDelegate(e, r), "throw" === r.method) || "return" !== n && (r.method = "throw", r.arg = new TypeError("The iterator does not provide a '" + n + "' method")), y; var i = tryCatch(o, e.iterator, r.arg); if ("throw" === i.type) return r.method = "throw", r.arg = i.arg, r.delegate = null, y; var a = i.arg; return a ? a.done ? (r[e.resultName] = a.value, r.next = e.nextLoc, "return" !== r.method && (r.method = "next", r.arg = t), r.delegate = null, y) : a : (r.method = "throw", r.arg = new TypeError("iterator result is not an object"), r.delegate = null, y); } function pushTryEntry(t) { var e = { tryLoc: t[0] }; 1 in t && (e.catchLoc = t[1]), 2 in t && (e.finallyLoc = t[2], e.afterLoc = t[3]), this.tryEntries.push(e); } function resetTryEntry(t) { var e = t.completion || {}; e.type = "normal", delete e.arg, t.completion = e; } function Context(t) { this.tryEntries = [{ tryLoc: "root" }], t.forEach(pushTryEntry, this), this.reset(!0); } function values(e) { if (e || "" === e) { var r = e[a]; if (r) return r.call(e); if ("function" == typeof e.next) return e; if (!isNaN(e.length)) { var o = -1, i = function next() { for (; ++o < e.length;) if (n.call(e, o)) return next.value = e[o], next.done = !1, next; return next.value = t, next.done = !0, next; }; return i.next = i; } } throw new TypeError(_typeof(e) + " is not iterable"); } return GeneratorFunction.prototype = GeneratorFunctionPrototype, o(g, "constructor", { value: GeneratorFunctionPrototype, configurable: !0 }), o(GeneratorFunctionPrototype, "constructor", { value: GeneratorFunction, configurable: !0 }), GeneratorFunction.displayName = define(GeneratorFunctionPrototype, u, "GeneratorFunction"), e.isGeneratorFunction = function (t) { var e = "function" == typeof t && t.constructor; return !!e && (e === GeneratorFunction || "GeneratorFunction" === (e.displayName || e.name)); }, e.mark = function (t) { return Object.setPrototypeOf ? Object.setPrototypeOf(t, GeneratorFunctionPrototype) : (t.__proto__ = GeneratorFunctionPrototype, define(t, u, "GeneratorFunction")), t.prototype = Object.create(g), t; }, e.awrap = function (t) { return { __await: t }; }, defineIteratorMethods(AsyncIterator.prototype), define(AsyncIterator.prototype, c, function () { return this; }), e.AsyncIterator = AsyncIterator, e.async = function (t, r, n, o, i) { void 0 === i && (i = Promise); var a = new AsyncIterator(wrap(t, r, n, o), i); return e.isGeneratorFunction(r) ? a : a.next().then(function (t) { return t.done ? t.value : a.next(); }); }, defineIteratorMethods(g), define(g, u, "Generator"), define(g, a, function () { return this; }), define(g, "toString", function () { return "[object Generator]"; }), e.keys = function (t) { var e = Object(t), r = []; for (var n in e) r.push(n); return r.reverse(), function next() { for (; r.length;) { var t = r.pop(); if (t in e) return next.value = t, next.done = !1, next; } return next.done = !0, next; }; }, e.values = values, Context.prototype = { constructor: Context, reset: function reset(e) { if (this.prev = 0, this.next = 0, this.sent = this._sent = t, this.done = !1, this.delegate = null, this.method = "next", this.arg = t, this.tryEntries.forEach(resetTryEntry), !e) for (var r in this) "t" === r.charAt(0) && n.call(this, r) && !isNaN(+r.slice(1)) && (this[r] = t); }, stop: function stop() { this.done = !0; var t = this.tryEntries[0].completion; if ("throw" === t.type) throw t.arg; return this.rval; }, dispatchException: function dispatchException(e) { if (this.done) throw e; var r = this; function handle(n, o) { return a.type = "throw", a.arg = e, r.next = n, o && (r.method = "next", r.arg = t), !!o; } for (var o = this.tryEntries.length - 1; o >= 0; --o) { var i = this.tryEntries[o], a = i.completion; if ("root" === i.tryLoc) return handle("end"); if (i.tryLoc <= this.prev) { var c = n.call(i, "catchLoc"), u = n.call(i, "finallyLoc"); if (c && u) { if (this.prev < i.catchLoc) return handle(i.catchLoc, !0); if (this.prev < i.finallyLoc) return handle(i.finallyLoc); } else if (c) { if (this.prev < i.catchLoc) return handle(i.catchLoc, !0); } else { if (!u) throw Error("try statement without catch or finally"); if (this.prev < i.finallyLoc) return handle(i.finallyLoc); } } } }, abrupt: function abrupt(t, e) { for (var r = this.tryEntries.length - 1; r >= 0; --r) { var o = this.tryEntries[r]; if (o.tryLoc <= this.prev && n.call(o, "finallyLoc") && this.prev < o.finallyLoc) { var i = o; break; } } i && ("break" === t || "continue" === t) && i.tryLoc <= e && e <= i.finallyLoc && (i = null); var a = i ? i.completion : {}; return a.type = t, a.arg = e, i ? (this.method = "next", this.next = i.finallyLoc, y) : this.complete(a); }, complete: function complete(t, e) { if ("throw" === t.type) throw t.arg; return "break" === t.type || "continue" === t.type ? this.next = t.arg : "return" === t.type ? (this.rval = this.arg = t.arg, this.method = "return", this.next = "end") : "normal" === t.type && e && (this.next = e), y; }, finish: function finish(t) { for (var e = this.tryEntries.length - 1; e >= 0; --e) { var r = this.tryEntries[e]; if (r.finallyLoc === t) return this.complete(r.completion, r.afterLoc), resetTryEntry(r), y; } }, "catch": function _catch(t) { for (var e = this.tryEntries.length - 1; e >= 0; --e) { var r = this.tryEntries[e]; if (r.tryLoc === t) { var n = r.completion; if ("throw" === n.type) { var o = n.arg; resetTryEntry(r); } return o; } } throw Error("illegal catch attempt"); }, delegateYield: function delegateYield(e, r, n) { return this.delegate = { iterator: values(e), resultName: r, nextLoc: n }, "next" === this.method && (this.arg = t), y; } }, e; }
function asyncGeneratorStep(n, t, e, r, o, a, c) { try { var i = n[a](c), u = i.value; } catch (n) { return void e(n); } i.done ? t(u) : Promise.resolve(u).then(r, o); }
function _asyncToGenerator(n) { return function () { var t = this, e = arguments; return new Promise(function (r, o) { var a = n.apply(t, e); function _next(n) { asyncGeneratorStep(a, r, o, _next, _throw, "next", n); } function _throw(n) { asyncGeneratorStep(a, r, o, _next, _throw, "throw", n); } _next(void 0); }); }; }
import express from 'express';
var purchaseOrder = express.Router();
import { authenticateApiKey } from '../../middleware/utils/apiKey.utils.js';
import { authenticateToken } from '../../middleware/utils/authToken.utils.js';
import Products from '../../model/Products.js';
import mongoose from 'mongoose';
import PurchaseOrder from '../../model/PurchaseOrder.js';
purchaseOrder.route("/purchase-order").get(authenticateApiKey, authenticateToken, /*#__PURE__*/function () {
  var _ref = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee(req, res) {
    var purchaseOrderData;
    return _regeneratorRuntime().wrap(function _callee$(_context) {
      while (1) switch (_context.prev = _context.next) {
        case 0:
          _context.prev = 0;
          _context.next = 3;
          return PurchaseOrder.find();
        case 3:
          purchaseOrderData = _context.sent;
          res.status(201).json(purchaseOrderData);
          _context.next = 10;
          break;
        case 7:
          _context.prev = 7;
          _context.t0 = _context["catch"](0);
          res.status(500).send("Error fetching user data: " + _context.t0.message);
        case 10:
        case "end":
          return _context.stop();
      }
    }, _callee, null, [[0, 7]]);
  }));
  return function (_x, _x2) {
    return _ref.apply(this, arguments);
  };
}());
purchaseOrder.route("/purchase-order").post(authenticateApiKey, authenticateToken, /*#__PURE__*/function () {
  var _ref2 = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee3(req, res) {
    var _req$body, name, address, companyName, phoneNo, paymentMode, quotationNo, poNo, products, extraDetails, session, productStockUpdates, _purchaseOrder;
    return _regeneratorRuntime().wrap(function _callee3$(_context3) {
      while (1) switch (_context3.prev = _context3.next) {
        case 0:
          _req$body = req.body, name = _req$body.name, address = _req$body.address, companyName = _req$body.companyName, phoneNo = _req$body.phoneNo, paymentMode = _req$body.paymentMode, quotationNo = _req$body.quotationNo, poNo = _req$body.poNo, products = _req$body.products, extraDetails = _req$body.extraDetails;
          if (!(!Array.isArray(products) || products.length === 0)) {
            _context3.next = 3;
            break;
          }
          return _context3.abrupt("return", res.status(400).json({
            message: 'Products array is required and cannot be empty'
          }));
        case 3:
          _context3.next = 5;
          return mongoose.startSession();
        case 5:
          session = _context3.sent;
          _context3.prev = 6;
          session.startTransaction();
          productStockUpdates = products.map( /*#__PURE__*/function () {
            var _ref3 = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee2(item) {
              var product;
              return _regeneratorRuntime().wrap(function _callee2$(_context2) {
                while (1) switch (_context2.prev = _context2.next) {
                  case 0:
                    _context2.next = 2;
                    return Products.findById(item.product);
                  case 2:
                    product = _context2.sent;
                    if (product) {
                      _context2.next = 6;
                      break;
                    }
                    res.status(400).res.json("Product with ID ".concat(item.product, " not found"));
                    throw new Error("Product with ID ".concat(item.product, " not found"));
                  case 6:
                    product.stock -= item.qty;
                    if (!(product.stock < 0)) {
                      _context2.next = 10;
                      break;
                    }
                    res.status(400).res.json("Insufficient stock for product: ".concat(item.name));
                    throw new Error("Insufficient stock for product: ".concat(item.name));
                  case 10:
                    _context2.next = 12;
                    return product.save({
                      session: session
                    });
                  case 12:
                  case "end":
                    return _context2.stop();
                }
              }, _callee2);
            }));
            return function (_x5) {
              return _ref3.apply(this, arguments);
            };
          }());
          _context3.next = 11;
          return Promise.all(productStockUpdates);
        case 11:
          _purchaseOrder = new PurchaseOrder({
            name: name,
            address: address,
            companyName: companyName,
            phoneNo: phoneNo,
            paymentMode: paymentMode,
            quotationNo: quotationNo,
            poNo: poNo,
            products: products,
            extraDetails: extraDetails
          });
          _context3.next = 14;
          return _purchaseOrder.save({
            session: session
          });
        case 14:
          _context3.next = 16;
          return session.commitTransaction();
        case 16:
          session.endSession();
          res.status(201).json({
            message: 'Purchase order created successfully'
          });
          _context3.next = 27;
          break;
        case 20:
          _context3.prev = 20;
          _context3.t0 = _context3["catch"](6);
          _context3.next = 24;
          return session.abortTransaction();
        case 24:
          session.endSession();
          console.error('Error creating purchase order:', _context3.t0);
          res.status(500).json({
            error: _context3.t0.message
          });
        case 27:
        case "end":
          return _context3.stop();
      }
    }, _callee3, null, [[6, 20]]);
  }));
  return function (_x3, _x4) {
    return _ref2.apply(this, arguments);
  };
}());
purchaseOrder.route('/purchase-order/:id').put(authenticateApiKey, authenticateToken, /*#__PURE__*/function () {
  var _ref4 = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee6(req, res) {
    var id, _req$body2, name, address, companyName, phoneNo, paymentMode, quotationNo, poNo, products, extraDetails, session, _purchaseOrder2, stockAdjustments, stockUpdates;
    return _regeneratorRuntime().wrap(function _callee6$(_context6) {
      while (1) switch (_context6.prev = _context6.next) {
        case 0:
          id = req.params.id;
          _req$body2 = req.body, name = _req$body2.name, address = _req$body2.address, companyName = _req$body2.companyName, phoneNo = _req$body2.phoneNo, paymentMode = _req$body2.paymentMode, quotationNo = _req$body2.quotationNo, poNo = _req$body2.poNo, products = _req$body2.products, extraDetails = _req$body2.extraDetails;
          _context6.next = 4;
          return mongoose.startSession();
        case 4:
          session = _context6.sent;
          console.log(req.body);
          _context6.prev = 6;
          session.startTransaction();
          _context6.next = 10;
          return PurchaseOrder.findById(id).session(session);
        case 10:
          _purchaseOrder2 = _context6.sent;
          if (_purchaseOrder2) {
            _context6.next = 13;
            break;
          }
          return _context6.abrupt("return", res.status(404).json({
            message: 'Purchase order entry not found'
          }));
        case 13:
          stockAdjustments = _purchaseOrder2.products.map( /*#__PURE__*/function () {
            var _ref5 = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee4(item) {
              var product;
              return _regeneratorRuntime().wrap(function _callee4$(_context4) {
                while (1) switch (_context4.prev = _context4.next) {
                  case 0:
                    _context4.next = 2;
                    return Products.findById(item.product).session(session);
                  case 2:
                    product = _context4.sent;
                    if (product) {
                      _context4.next = 5;
                      break;
                    }
                    throw new Error("Product with ID ".concat(item.product, " not found"));
                  case 5:
                    product.stock += item.qty;
                    _context4.next = 8;
                    return product.save({
                      session: session
                    });
                  case 8:
                  case "end":
                    return _context4.stop();
                }
              }, _callee4);
            }));
            return function (_x8) {
              return _ref5.apply(this, arguments);
            };
          }());
          _context6.next = 16;
          return Promise.all(stockAdjustments);
        case 16:
          stockUpdates = products.map( /*#__PURE__*/function () {
            var _ref6 = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee5(item) {
              var product;
              return _regeneratorRuntime().wrap(function _callee5$(_context5) {
                while (1) switch (_context5.prev = _context5.next) {
                  case 0:
                    _context5.next = 2;
                    return Products.findById(item.product).session(session);
                  case 2:
                    product = _context5.sent;
                    if (product) {
                      _context5.next = 5;
                      break;
                    }
                    throw new Error("Product with ID ".concat(item.product, " not found"));
                  case 5:
                    product.stock -= item.qty;
                    if (!(product.stock < 0)) {
                      _context5.next = 8;
                      break;
                    }
                    throw new Error("Insufficient stock for product: ".concat(item.name));
                  case 8:
                    _context5.next = 10;
                    return product.save({
                      session: session
                    });
                  case 10:
                  case "end":
                    return _context5.stop();
                }
              }, _callee5);
            }));
            return function (_x9) {
              return _ref6.apply(this, arguments);
            };
          }());
          _context6.next = 19;
          return Promise.all(stockUpdates);
        case 19:
          _purchaseOrder2.name = name;
          _purchaseOrder2.address = address;
          _purchaseOrder2.companyName = companyName;
          _purchaseOrder2.phoneNo = phoneNo;
          _purchaseOrder2.paymentMode = paymentMode;
          _purchaseOrder2.quotationNo = quotationNo;
          _purchaseOrder2.poNo = poNo;
          _purchaseOrder2.products = products;
          _purchaseOrder2.extraDetails = extraDetails;
          _context6.next = 30;
          return _purchaseOrder2.save({
            session: session
          });
        case 30:
          _context6.next = 32;
          return session.commitTransaction();
        case 32:
          session.endSession();
          res.status(200).json({
            message: 'Purchase order has been updated successfully'
          });
          _context6.next = 43;
          break;
        case 36:
          _context6.prev = 36;
          _context6.t0 = _context6["catch"](6);
          _context6.next = 40;
          return session.abortTransaction();
        case 40:
          session.endSession();
          console.error('Error updating purchase order entry:', _context6.t0);
          res.status(500).json({
            error: 'Internal server error'
          });
        case 43:
        case "end":
          return _context6.stop();
      }
    }, _callee6, null, [[6, 36]]);
  }));
  return function (_x6, _x7) {
    return _ref4.apply(this, arguments);
  };
}());
purchaseOrder.route('/purchase-order/:id')["delete"](authenticateApiKey, authenticateToken, /*#__PURE__*/function () {
  var _ref7 = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee8(req, res) {
    var id, cleanId, session, _purchaseOrder3, stockUpdates;
    return _regeneratorRuntime().wrap(function _callee8$(_context8) {
      while (1) switch (_context8.prev = _context8.next) {
        case 0:
          id = req.params.id;
          cleanId = id.replace('modal', '');
          _context8.next = 4;
          return mongoose.startSession();
        case 4:
          session = _context8.sent;
          _context8.prev = 5;
          session.startTransaction();
          _context8.next = 9;
          return PurchaseOrder.findById(cleanId).session(session);
        case 9:
          _purchaseOrder3 = _context8.sent;
          if (_purchaseOrder3) {
            _context8.next = 12;
            break;
          }
          return _context8.abrupt("return", res.status(404).json({
            error: 'Purchase order entry not found'
          }));
        case 12:
          stockUpdates = _purchaseOrder3.products.map( /*#__PURE__*/function () {
            var _ref8 = _asyncToGenerator( /*#__PURE__*/_regeneratorRuntime().mark(function _callee7(item) {
              var product;
              return _regeneratorRuntime().wrap(function _callee7$(_context7) {
                while (1) switch (_context7.prev = _context7.next) {
                  case 0:
                    _context7.next = 2;
                    return Products.findById(item.product).session(session);
                  case 2:
                    product = _context7.sent;
                    if (product) {
                      _context7.next = 5;
                      break;
                    }
                    throw new Error("Product with ID ".concat(item.product, " not found"));
                  case 5:
                    product.stock = product.stock + item.qty;
                    _context7.next = 8;
                    return product.save({
                      session: session
                    });
                  case 8:
                  case "end":
                    return _context7.stop();
                }
              }, _callee7);
            }));
            return function (_x12) {
              return _ref8.apply(this, arguments);
            };
          }());
          _context8.next = 15;
          return Promise.all(stockUpdates);
        case 15:
          _context8.next = 17;
          return PurchaseOrder.findByIdAndDelete(cleanId).session(session);
        case 17:
          _context8.next = 19;
          return session.commitTransaction();
        case 19:
          session.endSession();
          res.status(201).json({
            message: 'Purchase order has been deleted successfully'
          });
          _context8.next = 30;
          break;
        case 23:
          _context8.prev = 23;
          _context8.t0 = _context8["catch"](5);
          _context8.next = 27;
          return session.abortTransaction();
        case 27:
          session.endSession();
          console.error('Error deleting Purchase order entry:', _context8.t0);
          res.status(500).json({
            error: 'Internal server error'
          });
        case 30:
        case "end":
          return _context8.stop();
      }
    }, _callee8, null, [[5, 23]]);
  }));
  return function (_x10, _x11) {
    return _ref7.apply(this, arguments);
  };
}());
export default purchaseOrder;
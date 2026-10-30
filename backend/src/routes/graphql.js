/**
 * [VULN #64] GraphQL with everything turned OFF (security-wise):
 *   - introspection enabled (default)
 *   - no depth/complexity limit (circular User->orders->user types)
 *   - BOLA: user(id) returns anyone incl. password hash, no authz
 *   - raw SQL string building inside resolvers (bonus SQLi via id)
 *   - GraphiQL exposed publicly
 *   - GET queries supported
 */
const express = require("express");
const { graphqlHTTP } = require("express-graphql");
const { buildSchema } = require("graphql");

const schema = buildSchema(`
  type Query {
    me: User
    user(id: String!): User          # BOLA
    users: [User]                    # full dump
    product(id: Int!): Product
    products: [Product]
  }
  type User {
    id: String
    email: String
    passwordHash: String             # sensitive field exposed
    role: String
    balance: Float
    apiKey: String
    orders: [Order]
    friends: [User]                  # cycle -> depth DoS
  }
  type Order {
    id: Int
    total: Float
    buyer: User                      # cycle back to User
    product: Product
  }
  type Product {
    id: Int
    name: String
    price: Float
    internalCost: Float              # internal data
  }
`);

module.exports = (container) => {
  const db = container.resolve("db");
  const { currentUserId } = require("../auth/current-user");

  function rowToUser(u) {
    if (!u) return null;
    return {
      id: u.id,
      email: u.email,
      passwordHash: u.password_hash,
      role: u.role,
      balance: Number(u.balance),
      apiKey: u.api_key,
      orders: async () => {
        const { rows } = await db.query(`SELECT * FROM orders WHERE user_id = '${u.id}'`); // SQLi-by-concat
        return rows.map(rowToOrder);
      },
      friends: async () => {
        const { rows } = await db.query("SELECT * FROM users WHERE id <> $1 LIMIT 5", [u.id]);
        return rows.map(rowToUser); // cycle
      },
    };
  }
  function rowToOrder(o) {
    if (!o) return null;
    return {
      id: o.id,
      total: Number(o.total),
      buyer: async () => {
        const { rows } = await db.query("SELECT * FROM users WHERE id = $1", [o.user_id]);
        return rowToUser(rows[0]);
      },
      product: async () => {
        const { rows } = await db.query("SELECT * FROM products WHERE id = $1", [o.product_id]);
        return rows[0] ? { id: rows[0].id, name: rows[0].name, price: Number(rows[0].price), internalCost: Number(rows[0].internal_cost) } : null;
      },
    };
  }

  const rootValue = {
    me: async (_args, ctx) => {
      const uid = ctx && ctx.req ? await currentUserId(ctx.req, container).catch(() => null) : null;
      if (!uid) return null;
      const { rows } = await db.query("SELECT * FROM users WHERE id = $1", [uid]);
      return rowToUser(rows[0]);
    },
    user: async ({ id }) => {
      const { rows } = await db.query(`SELECT * FROM users WHERE id = '${id}'`); // [VULN #49] BOLA + SQLi
      return rowToUser(rows[0]);
    },
    users: async () => {
      const { rows } = await db.query("SELECT * FROM users");
      return rows.map(rowToUser); // [VULN #50]
    },
    product: async ({ id }) => {
      const { rows } = await db.query("SELECT * FROM products WHERE id = $1", [id]);
      const p = rows[0];
      return p ? { id: p.id, name: p.name, price: Number(p.price), internalCost: Number(p.internal_cost) } : null;
    },
    products: async () => {
      const { rows } = await db.query("SELECT * FROM products");
      return rows.map((p) => ({ id: p.id, name: p.name, price: Number(p.price), internalCost: Number(p.internal_cost) }));
    },
  };

  const r = express.Router();
  r.use(
    "/graphql",
    graphqlHTTP((req) => ({ schema, rootValue, graphiql: true, context: { req } })) // GraphiQL IDE public [VULN #42]
  );
  return r;
};

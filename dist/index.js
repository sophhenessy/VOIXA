var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import express5 from "express";

// server/routes.ts
import { createServer } from "http";

// server/auth.ts
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session from "express-session";
import createMemoryStore from "memorystore";
import { scrypt, timingSafeEqual } from "crypto";
import { promisify } from "util";

// db/schema.ts
var schema_exports = {};
__export(schema_exports, {
  follows: () => follows,
  groupMembers: () => groupMembers,
  groupMessages: () => groupMessages,
  groups: () => groups,
  insertFollowSchema: () => insertFollowSchema,
  insertGroupMemberSchema: () => insertGroupMemberSchema,
  insertGroupMessageSchema: () => insertGroupMessageSchema,
  insertGroupSchema: () => insertGroupSchema,
  insertTripPlaceSchema: () => insertTripPlaceSchema,
  insertTripSchema: () => insertTripSchema,
  insertUserSchema: () => insertUserSchema,
  likes: () => likes,
  recommendations: () => recommendations,
  reviewLikes: () => reviewLikes,
  reviews: () => reviews,
  selectFollowSchema: () => selectFollowSchema,
  selectGroupMemberSchema: () => selectGroupMemberSchema,
  selectGroupMessageSchema: () => selectGroupMessageSchema,
  selectGroupSchema: () => selectGroupSchema,
  selectTripPlaceSchema: () => selectTripPlaceSchema,
  selectTripSchema: () => selectTripSchema,
  selectUserSchema: () => selectUserSchema,
  tripPlaces: () => tripPlaces,
  trips: () => trips,
  users: () => users
});
import { pgTable, text, serial, integer, timestamp, jsonb, boolean } from "drizzle-orm/pg-core";
import { createInsertSchema, createSelectSchema } from "drizzle-zod";
import { z } from "zod";
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").unique().notNull(),
  password: text("password").notNull(),
  // Profile fields
  displayName: text("display_name"),
  bio: text("bio"),
  location: text("location"),
  avatarUrl: text("avatar_url"),
  // OAuth and account management
  resetToken: text("resetToken"),
  resetTokenExpiry: text("resetTokenExpiry"),
  preferences: jsonb("preferences").default({}).notNull()
});
var follows = pgTable("follows", {
  id: serial("id").primaryKey(),
  followerId: integer("follower_id").references(() => users.id).notNull(),
  followingId: integer("following_id").references(() => users.id).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var groups = pgTable("groups", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description"),
  avatarUrl: text("avatar_url"),
  createdBy: integer("created_by").references(() => users.id).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var groupMembers = pgTable("group_members", {
  id: serial("id").primaryKey(),
  groupId: integer("group_id").references(() => groups.id).notNull(),
  userId: integer("user_id").references(() => users.id).notNull(),
  role: text("role").default("member").notNull(),
  // 'admin' or 'member'
  joinedAt: timestamp("joined_at").defaultNow().notNull()
});
var groupMessages = pgTable("group_messages", {
  id: serial("id").primaryKey(),
  groupId: integer("group_id").references(() => groups.id).notNull(),
  userId: integer("user_id").references(() => users.id).notNull(),
  content: text("content").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var reviews = pgTable("reviews", {
  id: serial("id").primaryKey(),
  userId: serial("user_id").references(() => users.id),
  placeId: text("place_id").notNull(),
  placeName: text("place_name"),
  rating: integer("rating").notNull(),
  comment: text("comment"),
  isPublic: boolean("is_public").default(true).notNull(),
  groupId: integer("group_id").references(() => groups.id),
  location: jsonb("location").$type(),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var reviewLikes = pgTable("review_likes", {
  id: serial("id").primaryKey(),
  reviewId: serial("review_id").references(() => reviews.id),
  userId: serial("user_id").references(() => users.id),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var baseUserSchema = createSelectSchema(users);
var insertUserSchema = createInsertSchema(users);
var selectUserSchema = baseUserSchema.extend({
  message: z.string().optional()
});
var likes = pgTable("likes", {
  id: serial("id").primaryKey(),
  userId: serial("user_id").references(() => users.id),
  placeId: text("place_id").notNull(),
  placeName: text("place_name").notNull(),
  placeAddress: text("place_address"),
  placeType: text("place_type"),
  rating: integer("rating"),
  priceLevel: integer("price_level"),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var trips = pgTable("trips", {
  id: serial("id").primaryKey(),
  userId: serial("user_id").references(() => users.id),
  name: text("name").notNull(),
  description: text("description"),
  startDate: timestamp("start_date"),
  endDate: timestamp("end_date"),
  isPublic: boolean("is_public").default(false).notNull(),
  // Make location fields optional for existing records
  locationName: text("location_name"),
  locationLat: text("location_lat"),
  locationLng: text("location_lng"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull()
});
var tripPlaces = pgTable("trip_places", {
  id: serial("id").primaryKey(),
  tripId: serial("trip_id").references(() => trips.id),
  placeId: text("place_id").notNull(),
  placeName: text("place_name").notNull(),
  placeAddress: text("place_address"),
  notes: text("notes"),
  visitDate: timestamp("visit_date"),
  order: integer("order"),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var recommendations = pgTable("recommendations", {
  id: serial("id").primaryKey(),
  userId: serial("user_id").references(() => users.id),
  placeId: text("place_id").notNull(),
  placeName: text("place_name").notNull(),
  placeAddress: text("place_address"),
  placeType: text("place_type"),
  score: integer("score").notNull(),
  reason: text("reason").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull()
});
var insertTripSchema = createInsertSchema(trips);
var selectTripSchema = createSelectSchema(trips);
var insertTripPlaceSchema = createInsertSchema(tripPlaces);
var selectTripPlaceSchema = createSelectSchema(tripPlaces);
var insertFollowSchema = createInsertSchema(follows);
var selectFollowSchema = createSelectSchema(follows);
var insertGroupSchema = createInsertSchema(groups);
var selectGroupSchema = createSelectSchema(groups);
var insertGroupMemberSchema = createInsertSchema(groupMembers);
var selectGroupMemberSchema = createSelectSchema(groupMembers);
var insertGroupMessageSchema = createInsertSchema(groupMessages);
var selectGroupMessageSchema = createSelectSchema(groupMessages);

// db/index.ts
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?"
  );
}
var db = drizzle({
  connection: process.env.DATABASE_URL,
  schema: schema_exports,
  ws
});

// server/auth.ts
import { eq } from "drizzle-orm";
var scryptAsync = promisify(scrypt);
var MemoryStore = createMemoryStore(session);
function setupAuth(app2) {
  const sessionSettings = {
    secret: process.env.EXPRESS_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    name: "voxa.sid",
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1e3,
      // 24 hours
      sameSite: "lax",
      path: "/"
    },
    store: new MemoryStore({
      checkPeriod: 864e5
      // prune expired entries every 24h
    })
  };
  if (app2.get("env") === "production") {
    app2.set("trust proxy", 1);
    sessionSettings.cookie.secure = true;
  }
  app2.use(session(sessionSettings));
  app2.use(passport.initialize());
  app2.use(passport.session());
  passport.use(
    new LocalStrategy({
      usernameField: "email",
      passwordField: "password"
    }, async (email, password, done) => {
      try {
        const [user] = await db.select().from(users).where(eq(users.username, email)).limit(1);
        if (!user) {
          return done(null, false, { message: "Invalid credentials" });
        }
        const isMatch = await comparePasswords(password, user.password);
        if (!isMatch) {
          return done(null, false, { message: "Invalid credentials" });
        }
        return done(null, {
          id: user.id,
          username: user.username,
          displayName: user.displayName,
          bio: user.bio,
          location: user.location,
          avatarUrl: user.avatarUrl
        });
      } catch (err) {
        return done(err);
      }
    })
  );
  passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  passport.deserializeUser(async (id, done) => {
    try {
      const [user] = await db.select({
        id: users.id,
        username: users.username,
        displayName: users.displayName,
        bio: users.bio,
        location: users.location,
        avatarUrl: users.avatarUrl
      }).from(users).where(eq(users.id, id)).limit(1);
      if (!user) {
        return done(null, false);
      }
      done(null, user);
    } catch (err) {
      done(err);
    }
  });
  async function comparePasswords(supplied, stored) {
    const [hashedPassword, salt] = stored.split(".");
    const hashedPasswordBuf = Buffer.from(hashedPassword, "hex");
    const suppliedPasswordBuf = await scryptAsync(
      supplied,
      salt,
      64
    );
    return timingSafeEqual(hashedPasswordBuf, suppliedPasswordBuf);
  }
  app2.post("/api/login", (req, res, next) => {
    passport.authenticate("local", (err, user, info) => {
      if (err) {
        console.error("Login error:", err);
        return res.status(500).json({ error: "Internal server error" });
      }
      if (!user) {
        return res.status(401).json({ error: info?.message || "Login failed" });
      }
      req.login(user, (err2) => {
        if (err2) {
          console.error("Session error:", err2);
          return res.status(500).json({ error: "Failed to establish session" });
        }
        return res.json({
          message: "Login successful",
          user: {
            id: user.id,
            username: user.username,
            displayName: user.displayName,
            avatarUrl: user.avatarUrl
          }
        });
      });
    })(req, res, next);
  });
  app2.post("/api/logout", (req, res) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ error: "Logout failed" });
      }
      req.session.destroy((err2) => {
        if (err2) {
          return res.status(500).json({ error: "Logout failed" });
        }
        res.clearCookie("voxa.sid");
        res.json({ message: "Logout successful" });
      });
    });
  });
  app2.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Not logged in" });
    }
    const user = req.user;
    res.json({
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      avatarUrl: user.avatarUrl
    });
  });
}

// server/likes.ts
import { Router } from "express";
import { eq as eq2, desc, and } from "drizzle-orm";
var router = Router();
var requireAuth = (req, res, next) => {
  if (!req.user?.id) {
    return res.status(401).json({ error: "Not logged in" });
  }
  next();
};
router.use(requireAuth);
router.use((req, res, next) => {
  res.setHeader("Content-Type", "application/json");
  next();
});
router.get("/likes", async (req, res) => {
  try {
    const userId = req.user.id;
    console.log("Fetching likes for user:", userId);
    const userLikes = await db.select({
      id: likes.id,
      placeId: likes.placeId,
      placeName: likes.placeName,
      placeAddress: likes.placeAddress
    }).from(likes).where(eq2(likes.userId, userId)).orderBy(desc(likes.createdAt));
    console.log("Found likes:", userLikes);
    res.json(userLikes || []);
  } catch (error) {
    console.error("Error fetching likes:", error);
    res.status(500).json({
      error: "Failed to fetch likes",
      details: error instanceof Error ? error.message : "Unknown error"
    });
  }
});
router.post("/likes", async (req, res) => {
  try {
    console.log("Received like request body:", req.body);
    const { placeId, placeName, placeAddress, placeType, rating, priceLevel } = req.body;
    const userId = req.user.id;
    if (!placeId || !placeName) {
      console.error("Missing required fields:", { placeId, placeName });
      return res.status(400).json({
        error: "Missing required fields",
        details: {
          placeId: !placeId ? "Place ID is required" : null,
          placeName: !placeName ? "Place name is required" : null
        }
      });
    }
    const existingLike = await db.select().from(likes).where(and(
      eq2(likes.userId, userId),
      eq2(likes.placeId, placeId)
    )).limit(1);
    if (existingLike.length > 0) {
      return res.status(400).json({ error: "Place already liked" });
    }
    console.log("Inserting like with data:", {
      userId,
      placeId,
      placeName,
      placeAddress,
      placeType,
      rating,
      priceLevel
    });
    const result = await db.insert(likes).values({
      userId,
      placeId,
      placeName,
      placeAddress,
      placeType,
      rating,
      priceLevel,
      createdAt: /* @__PURE__ */ new Date()
    });
    console.log("Insert result:", result);
    res.json({ message: "Place liked successfully" });
  } catch (error) {
    console.error("Error liking place:", error);
    res.status(500).json({
      error: "Failed to like place",
      details: error instanceof Error ? error.message : "Unknown error"
    });
  }
});
router.delete("/likes/:placeId", async (req, res) => {
  try {
    const userId = req.user.id;
    const placeId = req.params.placeId;
    await db.delete(likes).where(and(
      eq2(likes.userId, userId),
      eq2(likes.placeId, placeId)
    ));
    res.json({ message: "Place unliked successfully" });
  } catch (error) {
    console.error("Error unliking place:", error);
    res.status(500).json({
      error: "Failed to unlike place",
      details: error instanceof Error ? error.message : "Unknown error"
    });
  }
});

// server/recommendations.ts
import { Router as Router2 } from "express";
import { eq as eq3, desc as desc2, and as and2, sql } from "drizzle-orm";
var router2 = Router2();
function calculateScore(userPreferences, placeType, rating, priceLevel) {
  let score = 0;
  score += (userPreferences[placeType] || 0) * 2;
  score += rating * 10;
  if (userPreferences.preferredPriceLevel === priceLevel) {
    score += 20;
  }
  return score;
}
router2.get("/api/recommendations", async (req, res) => {
  try {
    if (!req.user?.id) {
      return res.status(401).json({ error: "Not logged in" });
    }
    const userLikes = await db.select().from(likes).where(eq3(likes.userId, req.user.id)).orderBy(desc2(likes.createdAt));
    const preferences = {};
    userLikes.forEach((like) => {
      if (like.placeType) {
        preferences[like.placeType] = (preferences[like.placeType] || 0) + 1;
      }
    });
    const recommendations3 = await Promise.all(
      Object.entries(preferences).sort(([, a], [, b]) => b - a).slice(0, 3).map(async ([placeType]) => {
        const similarPlaces = await db.select().from(likes).where(
          and2(
            eq3(likes.placeType, placeType),
            sql`${likes.userId} != ${req.user.id}`
          )
        ).limit(5);
        return similarPlaces.map((place) => ({
          ...place,
          score: calculateScore(
            preferences,
            place.placeType || "",
            place.rating || 0,
            place.priceLevel || 0
          ),
          reason: `Based on your interest in ${placeType.toLowerCase().replace("_", " ")} places`
        }));
      })
    );
    const flattenedRecommendations = recommendations3.flat().sort((a, b) => b.score - a.score).slice(0, 10);
    res.json(flattenedRecommendations);
  } catch (error) {
    console.error("Error generating recommendations:", error);
    res.status(500).json({ error: "Failed to generate recommendations" });
  }
});

// server/reviews.ts
import { Router as Router3 } from "express";
import { eq as eq4, desc as desc3, and as and3, count, sql as sql2 } from "drizzle-orm";
function calculateDistance(lat1, lon1, lat2, lon2) {
  try {
    const coords = [lat1, lon1, lat2, lon2];
    if (coords.some((coord) => coord === void 0 || coord === null || isNaN(coord))) {
      console.log("Invalid coordinates:", { lat1, lon1, lat2, lon2 });
      return void 0;
    }
    const lat1Rad = lat1 * Math.PI / 180;
    const lon1Rad = lon1 * Math.PI / 180;
    const lat2Rad = lat2 * Math.PI / 180;
    const lon2Rad = lon2 * Math.PI / 180;
    const R = 6371;
    const dLat = lat2Rad - lat1Rad;
    const dLon = lon2Rad - lon1Rad;
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) + Math.cos(lat1Rad) * Math.cos(lat2Rad) * Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    const distance = R * c;
    return Number(distance.toFixed(1));
  } catch (error) {
    console.error("Error calculating distance:", error);
    return void 0;
  }
}
function processLocation(location, userLat, userLng) {
  try {
    if (!location || typeof location !== "object") {
      console.log("Invalid location object:", location);
      return null;
    }
    if (!location.coordinates?.lat || !location.coordinates?.lng) {
      console.log("Missing coordinates:", location);
      return null;
    }
    const processedLocation = {
      coordinates: {
        lat: Number(location.coordinates.lat),
        lng: Number(location.coordinates.lng)
      },
      formatted_address: location.formatted_address || ""
    };
    if (typeof userLat === "number" && typeof userLng === "number") {
      const distance = calculateDistance(
        userLat,
        userLng,
        processedLocation.coordinates.lat,
        processedLocation.coordinates.lng
      );
      if (distance !== void 0) {
        processedLocation.distance = distance;
        console.log("Calculated distance:", distance, "km");
      }
    }
    return processedLocation;
  } catch (error) {
    console.error("Error processing location:", error);
    return null;
  }
}
var router3 = Router3();
router3.get("/community", async (req, res) => {
  try {
    const userId = req.user?.id;
    const userLat = req.query.userLat ? parseFloat(req.query.userLat) : void 0;
    const userLng = req.query.userLng ? parseFloat(req.query.userLng) : void 0;
    console.log("Processing community reviews with coordinates:", { userLat, userLng });
    const communityReviews = await db.select({
      id: reviews.id,
      placeId: reviews.placeId,
      placeName: reviews.placeName,
      rating: reviews.rating,
      comment: reviews.comment,
      createdAt: reviews.createdAt,
      username: users.username,
      location: reviews.location,
      groupId: reviews.groupId,
      groupName: sql2`(
          SELECT name FROM ${groupMembers}
          JOIN groups ON groups.id = group_members.group_id
          WHERE group_members.group_id = ${reviews.groupId}
          LIMIT 1
        )`.as("group_name"),
      likes: count(reviewLikes.id).as("likes_count"),
      isLiked: userId ? sql2`EXISTS (
            SELECT 1 FROM ${reviewLikes} rl
            WHERE rl.review_id = ${reviews.id}
            AND rl.user_id = ${userId}
          )`.as("is_liked") : sql2`false`.as("is_liked")
    }).from(reviews).innerJoin(users, eq4(reviews.userId, users.id)).leftJoin(reviewLikes, eq4(reviews.id, reviewLikes.reviewId)).where(eq4(reviews.isPublic, true)).groupBy(
      reviews.id,
      users.id,
      users.username,
      reviews.placeId,
      reviews.placeName,
      reviews.rating,
      reviews.comment,
      reviews.createdAt,
      reviews.location,
      reviews.groupId
    ).orderBy(desc3(reviews.createdAt));
    const formattedReviews = communityReviews.map((review) => {
      const location = review.location ? processLocation(review.location, userLat, userLng) : null;
      console.log("Processed location for review:", {
        reviewId: review.id,
        location,
        originalLocation: review.location
      });
      return {
        ...review,
        location
      };
    });
    console.log("Sending formatted reviews:", JSON.stringify(formattedReviews, null, 2));
    res.json(formattedReviews);
  } catch (error) {
    console.error("Error fetching community reviews:", error);
    res.status(500).json({ message: "Failed to fetch reviews" });
  }
});
router3.get("/following", async (req, res) => {
  try {
    if (!req.user?.id) {
      return res.status(401).json({ message: "Not authenticated" });
    }
    const userLat = req.query.userLat ? parseFloat(req.query.userLat) : void 0;
    const userLng = req.query.userLng ? parseFloat(req.query.userLng) : void 0;
    const followingReviews = await db.select({
      id: reviews.id,
      placeId: reviews.placeId,
      placeName: reviews.placeName,
      rating: reviews.rating,
      comment: reviews.comment,
      createdAt: reviews.createdAt,
      username: users.username,
      location: reviews.location,
      likes: count(reviewLikes.id).as("likes_count"),
      isLiked: sql2`EXISTS (
          SELECT 1 FROM ${reviewLikes} rl
          WHERE rl.review_id = ${reviews.id}
          AND rl.user_id = ${req.user.id}
        )`.as("is_liked")
    }).from(reviews).innerJoin(users, eq4(reviews.userId, users.id)).leftJoin(reviewLikes, eq4(reviews.id, reviewLikes.reviewId)).innerJoin(follows, eq4(reviews.userId, follows.followingId)).where(and3(
      eq4(follows.followerId, req.user.id),
      eq4(reviews.isPublic, true)
    )).groupBy(
      reviews.id,
      users.id,
      users.username,
      reviews.placeId,
      reviews.placeName,
      reviews.rating,
      reviews.comment,
      reviews.createdAt,
      reviews.location
    ).orderBy(desc3(reviews.createdAt));
    const formattedReviews = followingReviews.map((review) => ({
      ...review,
      location: processLocation(review.location, userLat, userLng)
    }));
    res.json(formattedReviews);
  } catch (error) {
    console.error("Error fetching following reviews:", error);
    res.status(500).json({ message: "Failed to fetch reviews" });
  }
});
router3.get("/place/:placeId", async (req, res) => {
  try {
    const { placeId } = req.params;
    const userLat = req.query.userLat ? parseFloat(req.query.userLat) : void 0;
    const userLng = req.query.userLng ? parseFloat(req.query.userLng) : void 0;
    console.log("Processing request with coordinates:", { userLat, userLng });
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    const placeReviews = await db.select({
      id: reviews.id,
      placeId: reviews.placeId,
      placeName: reviews.placeName,
      rating: reviews.rating,
      comment: reviews.comment,
      createdAt: reviews.createdAt,
      username: users.username,
      location: reviews.location
    }).from(reviews).leftJoin(users, eq4(reviews.userId, users.id)).where(eq4(reviews.placeId, placeId)).orderBy(desc3(reviews.createdAt));
    const formattedReviews = placeReviews.map((review) => ({
      ...review,
      location: review.location ? processLocation(review.location, userLat, userLng) : null
    }));
    console.log("Sending formatted reviews:", JSON.stringify(formattedReviews, null, 2));
    res.json(formattedReviews);
  } catch (error) {
    console.error("Error fetching place reviews:", error);
    res.status(500).json({ error: "Failed to fetch reviews" });
  }
});
router3.post("/:reviewId/like", async (req, res) => {
  try {
    if (!req.user?.id) {
      return res.status(401).json({ message: "Not authenticated" });
    }
    const { reviewId } = req.params;
    const existingLike = await db.select().from(reviewLikes).where(and3(
      eq4(reviewLikes.reviewId, parseInt(reviewId)),
      eq4(reviewLikes.userId, req.user.id)
    )).limit(1);
    if (existingLike.length > 0) {
      return res.status(400).json({ message: "Already liked this review" });
    }
    await db.insert(reviewLikes).values({
      reviewId: parseInt(reviewId),
      userId: req.user.id
    });
    res.status(201).json({ message: "Review liked successfully" });
  } catch (error) {
    console.error("Error liking review:", error);
    res.status(500).json({ message: "Failed to like review" });
  }
});
router3.delete("/:reviewId/like", async (req, res) => {
  try {
    if (!req.user?.id) {
      return res.status(401).json({ message: "Not authenticated" });
    }
    const { reviewId } = req.params;
    await db.delete(reviewLikes).where(and3(
      eq4(reviewLikes.reviewId, parseInt(reviewId)),
      eq4(reviewLikes.userId, req.user.id)
    ));
    res.status(204).send();
  } catch (error) {
    console.error("Error unliking review:", error);
    res.status(500).json({ message: "Failed to unlike review" });
  }
});
router3.get("/", async (req, res) => {
  try {
    if (!req.user?.id) {
      return res.status(401).json({ message: "Not authenticated" });
    }
    const userReviews = await db.select({
      id: reviews.id,
      placeId: reviews.placeId,
      placeName: reviews.placeName,
      rating: reviews.rating,
      comment: reviews.comment,
      createdAt: reviews.createdAt,
      likes: count(reviewLikes.id)
    }).from(reviews).leftJoin(reviewLikes, eq4(reviews.id, reviewLikes.reviewId)).where(eq4(reviews.userId, req.user.id)).groupBy(reviews.id).orderBy(desc3(reviews.createdAt));
    res.json(userReviews);
  } catch (error) {
    console.error("Error fetching user reviews:", error);
    res.status(500).json({ message: "Failed to fetch reviews" });
  }
});
router3.post("/", async (req, res) => {
  try {
    if (!req.user?.id) {
      console.log("User not authenticated");
      return res.status(401).json({ message: "Not authenticated" });
    }
    const { placeId, rating, comment, placeName, location, groupId } = req.body;
    console.log("Received review data:", { placeId, rating, comment, placeName, location, groupId });
    if (!placeId || !rating) {
      return res.status(400).json({ message: "Missing required fields" });
    }
    if (groupId) {
      const groupMember = await db.select().from(groupMembers).where(and3(
        eq4(groupMembers.groupId, groupId),
        eq4(groupMembers.userId, req.user.id)
      )).limit(1);
      if (groupMember.length === 0) {
        return res.status(403).json({ message: "Not a member of this group" });
      }
    }
    const processedLocation = processLocation(location);
    if (!processedLocation) {
      console.error("Invalid location data:", location);
      return res.status(400).json({ message: "Invalid location data" });
    }
    const newReview = await db.insert(reviews).values({
      userId: req.user.id,
      placeId,
      rating,
      comment: comment || "",
      placeName: placeName || null,
      location: processedLocation,
      isPublic: true,
      groupId: groupId || null
    }).returning();
    console.log("Created review with location:", processedLocation);
    const createdReview = {
      ...newReview[0],
      username: req.user.username,
      location: processedLocation
    };
    res.status(201).json(createdReview);
  } catch (error) {
    console.error("Error creating review:", error);
    res.status(500).json({ message: "Failed to create review" });
  }
});
router3.put("/:id", async (req, res) => {
  try {
    if (!req.user?.id) {
      return res.status(401).json({ message: "Not authenticated" });
    }
    const { id } = req.params;
    const { rating, comment } = req.body;
    const review = await db.select().from(reviews).where(and3(
      eq4(reviews.id, parseInt(id)),
      eq4(reviews.userId, req.user.id)
    )).limit(1);
    if (review.length === 0) {
      return res.status(403).json({ message: "Not authorized to update this review" });
    }
    const updatedReview = await db.update(reviews).set({ rating, comment }).where(eq4(reviews.id, parseInt(id))).returning();
    res.json(updatedReview[0]);
  } catch (error) {
    console.error("Error updating review:", error);
    res.status(500).json({ message: "Failed to update review" });
  }
});
router3.delete("/:id", async (req, res) => {
  try {
    if (!req.user?.id) {
      return res.status(401).json({ message: "Not authenticated" });
    }
    const { id } = req.params;
    const review = await db.select().from(reviews).where(and3(
      eq4(reviews.id, parseInt(id)),
      eq4(reviews.userId, req.user.id)
    )).limit(1);
    if (review.length === 0) {
      return res.status(403).json({ message: "Not authorized to delete this review" });
    }
    await db.delete(reviewLikes).where(eq4(reviewLikes.reviewId, parseInt(id)));
    await db.delete(reviews).where(eq4(reviews.id, parseInt(id)));
    res.status(204).send();
  } catch (error) {
    console.error("Error deleting review:", error);
    res.status(500).json({ message: "Failed to delete review" });
  }
});
router3.get("/search/users", async (req, res) => {
  try {
    const { query } = req.query;
    if (!query) {
      return res.json([]);
    }
    const searchResults = await db.select({
      id: users.id,
      username: users.username,
      displayName: users.displayName,
      avatarUrl: users.avatarUrl,
      bio: users.bio
    }).from(users).where(
      sql2`LOWER(${users.username}) LIKE LOWER(${"%" + query + "%"}) 
        OR LOWER(${users.displayName}) LIKE LOWER(${"%" + query + "%"})`
    ).limit(10);
    res.json(searchResults);
  } catch (error) {
    console.error("Error searching users:", error);
    res.status(500).json({ message: "Failed to search users" });
  }
});
var reviews_default = router3;

// server/trips.ts
import express from "express";
import { eq as eq5, and as and4, desc as desc4 } from "drizzle-orm";
var router4 = express.Router();
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.status(401).json({ error: "Not logged in" });
}
router4.get("/public", async (req, res) => {
  try {
    console.log("Fetching public trips");
    const publicTrips = await db.query.trips.findMany({
      where: eq5(trips.isPublic, true),
      orderBy: [desc4(trips.createdAt)]
    });
    console.log("Found public trips:", publicTrips);
    const tripsWithPlacesCount = await Promise.all(
      publicTrips.map(async (trip) => {
        const places = await db.query.tripPlaces.findMany({
          where: eq5(tripPlaces.tripId, trip.id)
        });
        const user = await db.query.users.findFirst({
          where: eq5(users.id, trip.userId),
          columns: {
            username: true
          }
        });
        console.log(`Processing trip ${trip.id}:`, {
          places: places.length,
          username: user?.username
        });
        return {
          ...trip,
          username: user?.username,
          placesCount: places.length
        };
      })
    );
    console.log("Sending processed trips:", tripsWithPlacesCount);
    res.json(tripsWithPlacesCount);
  } catch (error) {
    console.error("Error fetching public trips:", error);
    res.status(500).json({ error: "Failed to fetch public trips" });
  }
});
router4.get("/shared/:id", async (req, res) => {
  try {
    console.log("Fetching shared trip:", req.params.id);
    const trip = await db.query.trips.findFirst({
      where: and4(
        eq5(trips.id, parseInt(req.params.id)),
        eq5(trips.isPublic, true)
      )
    });
    if (!trip) {
      return res.status(404).json({ error: "Trip not found or is private" });
    }
    const user = await db.query.users.findFirst({
      where: eq5(users.id, trip.userId),
      columns: {
        username: true
      }
    });
    const places = await db.query.tripPlaces.findMany({
      where: eq5(tripPlaces.tripId, trip.id)
    });
    console.log("Found shared trip:", { ...trip, username: user?.username, places });
    res.json({
      ...trip,
      username: user?.username,
      places
    });
  } catch (error) {
    console.error("Error fetching shared trip:", error);
    res.status(500).json({ error: "Failed to fetch shared trip" });
  }
});
router4.get("/", ensureAuthenticated, async (req, res) => {
  try {
    const userTrips = await db.query.trips.findMany({
      where: eq5(trips.userId, req.user.id),
      orderBy: [desc4(trips.createdAt)]
    });
    res.json(userTrips);
  } catch (error) {
    console.error("Error fetching trips:", error);
    res.status(500).json({ error: "Failed to fetch trips" });
  }
});
router4.get("/:id", ensureAuthenticated, async (req, res) => {
  try {
    const trip = await db.query.trips.findFirst({
      where: eq5(trips.id, parseInt(req.params.id))
    });
    if (!trip) {
      return res.status(404).json({ error: "Trip not found" });
    }
    if (trip.userId !== req.user.id) {
      return res.status(403).json({ error: "Not authorized to view this trip" });
    }
    const places = await db.query.tripPlaces.findMany({
      where: eq5(tripPlaces.tripId, trip.id)
    });
    res.json({ ...trip, places });
  } catch (error) {
    console.error("Error fetching trip:", error);
    res.status(500).json({ error: "Failed to fetch trip" });
  }
});
router4.post("/", ensureAuthenticated, async (req, res) => {
  try {
    const { name, description, startDate, endDate, isPublic } = req.body;
    const [newTrip] = await db.insert(trips).values({
      userId: req.user.id,
      name,
      description,
      startDate: startDate ? new Date(startDate) : null,
      endDate: endDate ? new Date(endDate) : null,
      isPublic: isPublic || false
    }).returning();
    res.json(newTrip);
  } catch (error) {
    console.error("Error creating trip:", error);
    res.status(500).json({ error: "Failed to create trip" });
  }
});
router4.patch("/:id", ensureAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, startDate, endDate, isPublic } = req.body;
    const trip = await db.query.trips.findFirst({
      where: eq5(trips.id, parseInt(id))
    });
    if (!trip) {
      return res.status(404).json({ error: "Trip not found" });
    }
    if (trip.userId !== req.user.id) {
      return res.status(403).json({ error: "Not authorized to update this trip" });
    }
    const [updatedTrip] = await db.update(trips).set({
      name: name !== void 0 ? name : trip.name,
      description: description !== void 0 ? description : trip.description,
      startDate: startDate !== void 0 ? startDate : trip.startDate,
      endDate: endDate !== void 0 ? endDate : trip.endDate,
      isPublic: isPublic !== void 0 ? isPublic : trip.isPublic
    }).where(eq5(trips.id, parseInt(id))).returning();
    res.json(updatedTrip);
  } catch (error) {
    console.error("Error updating trip:", error);
    res.status(500).json({ error: "Failed to update trip" });
  }
});
var tripsRouter = router4;

// server/social.ts
import express2 from "express";
import { eq as eq6, and as and5, desc as desc5, sql as sql3 } from "drizzle-orm";
var router5 = express2.Router();
router5.get("/users/:username/stats", async (req, res) => {
  try {
    const user = await db.query.users.findFirst({
      where: eq6(users.username, req.params.username)
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const followersCount = await db.select({ count: sql3`count(*)` }).from(follows).where(eq6(follows.followingId, user.id)).then((result) => Number(result[0].count));
    const followingCount = await db.select({ count: sql3`count(*)` }).from(follows).where(eq6(follows.followerId, user.id)).then((result) => Number(result[0].count));
    res.json({
      followersCount,
      followingCount
    });
  } catch (error) {
    console.error("Error fetching social stats:", error);
    res.status(500).json({ error: "Failed to fetch social stats" });
  }
});
router5.get("/users/:username/public", async (req, res) => {
  try {
    const user = await db.query.users.findFirst({
      where: eq6(users.username, req.params.username),
      columns: {
        id: true,
        username: true,
        displayName: true,
        bio: true,
        location: true,
        avatarUrl: true
      }
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const followersCount = await db.select({ count: sql3`count(*)` }).from(follows).where(eq6(follows.followingId, user.id)).then((result) => result[0].count);
    const followingCount = await db.select({ count: sql3`count(*)` }).from(follows).where(eq6(follows.followerId, user.id)).then((result) => result[0].count);
    const publicTripsCount = await db.select({ count: sql3`count(*)` }).from(trips).where(and5(
      eq6(trips.userId, user.id),
      eq6(trips.isPublic, true)
    )).then((result) => result[0].count);
    const publicReviewsCount = await db.select({ count: sql3`count(*)` }).from(reviews).where(and5(
      eq6(reviews.userId, user.id),
      eq6(reviews.isPublic, true)
    )).then((result) => result[0].count);
    let isFollowing = false;
    const authenticatedReq = req;
    if (authenticatedReq.isAuthenticated() && authenticatedReq.user) {
      const followRecord = await db.query.follows.findFirst({
        where: and5(
          eq6(follows.followerId, authenticatedReq.user.id),
          eq6(follows.followingId, user.id)
        )
      });
      isFollowing = !!followRecord;
    }
    res.json({
      ...user,
      followersCount,
      followingCount,
      publicTripsCount,
      publicReviewsCount,
      isFollowing
    });
  } catch (error) {
    console.error("Error fetching public profile:", error);
    res.status(500).json({ error: "Failed to fetch public profile" });
  }
});
router5.get("/users/:username", async (req, res) => {
  try {
    const user = await db.query.users.findFirst({
      where: eq6(users.username, req.params.username),
      columns: {
        id: true,
        username: true,
        displayName: true,
        bio: true,
        location: true,
        avatarUrl: true
      }
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const followersCount = await db.select({ count: sql3`count(*)` }).from(follows).where(eq6(follows.followingId, user.id)).then((result) => result[0].count);
    const followingCount = await db.select({ count: sql3`count(*)` }).from(follows).where(eq6(follows.followerId, user.id)).then((result) => result[0].count);
    let isFollowing = false;
    const authenticatedReq = req;
    if (authenticatedReq.isAuthenticated() && authenticatedReq.user) {
      const followRecord = await db.query.follows.findFirst({
        where: and5(
          eq6(follows.followerId, authenticatedReq.user.id),
          eq6(follows.followingId, user.id)
        )
      });
      isFollowing = !!followRecord;
    }
    res.json({
      ...user,
      followersCount,
      followingCount,
      isFollowing
    });
  } catch (error) {
    console.error("Error fetching user profile:", error);
    res.status(500).json({ error: "Failed to fetch user profile" });
  }
});
router5.post("/social/follow/:userId", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  try {
    const targetUserId = parseInt(req.params.userId);
    if (targetUserId === req.user.id) {
      return res.status(400).json({ error: "Cannot follow yourself" });
    }
    const targetUser = await db.query.users.findFirst({
      where: eq6(users.id, targetUserId)
    });
    if (!targetUser) {
      return res.status(404).json({ error: "User not found" });
    }
    const existingFollow = await db.query.follows.findFirst({
      where: and5(
        eq6(follows.followerId, req.user.id),
        eq6(follows.followingId, targetUserId)
      )
    });
    if (existingFollow) {
      return res.status(400).json({ error: "Already following this user" });
    }
    await db.insert(follows).values({
      followerId: req.user.id,
      followingId: targetUserId
    });
    res.json({ message: "Successfully followed user" });
  } catch (error) {
    console.error("Error following user:", error);
    res.status(500).json({ error: "Failed to follow user" });
  }
});
router5.post("/social/unfollow/:userId", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  try {
    const targetUserId = parseInt(req.params.userId);
    if (targetUserId === req.user.id) {
      return res.status(400).json({ error: "Cannot unfollow yourself" });
    }
    const targetUser = await db.query.users.findFirst({
      where: eq6(users.id, targetUserId)
    });
    if (!targetUser) {
      return res.status(404).json({ error: "User not found" });
    }
    await db.delete(follows).where(
      and5(
        eq6(follows.followerId, req.user.id),
        eq6(follows.followingId, targetUserId)
      )
    );
    res.json({ message: "Successfully unfollowed user" });
  } catch (error) {
    console.error("Error unfollowing user:", error);
    res.status(500).json({ error: "Failed to unfollow user" });
  }
});
router5.get("/users/:username/followers", async (req, res) => {
  try {
    const user = await db.query.users.findFirst({
      where: eq6(users.username, req.params.username)
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const followers = await db.select({
      id: users.id,
      username: users.username,
      displayName: users.displayName,
      bio: users.bio,
      avatarUrl: users.avatarUrl
    }).from(follows).innerJoin(users, eq6(follows.followerId, users.id)).where(eq6(follows.followingId, user.id));
    res.json(followers);
  } catch (error) {
    console.error("Error fetching followers:", error);
    res.status(500).json({ error: "Failed to fetch followers" });
  }
});
router5.get("/users/:username/following", async (req, res) => {
  try {
    const user = await db.query.users.findFirst({
      where: eq6(users.username, req.params.username)
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const following = await db.select({
      id: users.id,
      username: users.username,
      displayName: users.displayName,
      bio: users.bio,
      avatarUrl: users.avatarUrl
    }).from(follows).innerJoin(users, eq6(follows.followingId, users.id)).where(eq6(follows.followerId, user.id));
    res.json(following);
  } catch (error) {
    console.error("Error fetching following:", error);
    res.status(500).json({ error: "Failed to fetch following" });
  }
});
router5.get("/users/:username/trips", async (req, res) => {
  try {
    const user = await db.query.users.findFirst({
      where: eq6(users.username, req.params.username)
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const userTrips = await db.query.trips.findMany({
      where: and5(
        eq6(trips.userId, user.id),
        eq6(trips.isPublic, true)
      ),
      orderBy: [desc5(trips.createdAt)]
    });
    res.json(userTrips);
  } catch (error) {
    console.error("Error fetching user trips:", error);
    res.status(500).json({ error: "Failed to fetch user trips" });
  }
});
router5.get("/users/:username/reviews", async (req, res) => {
  try {
    const user = await db.query.users.findFirst({
      where: eq6(users.username, req.params.username)
    });
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    const userReviews = await db.query.reviews.findMany({
      where: eq6(reviews.userId, user.id),
      orderBy: [desc5(reviews.createdAt)]
    });
    res.json(userReviews);
  } catch (error) {
    console.error("Error fetching user reviews:", error);
    res.status(500).json({ error: "Failed to fetch user reviews" });
  }
});
var socialRouter = router5;

// server/groups.ts
import { Router as Router4 } from "express";
import { eq as eq7, and as and6, desc as desc6, sql as sql4 } from "drizzle-orm";
import multer from "multer";
import path from "path";
var router6 = Router4();
var storage = multer.diskStorage({
  destination: "./uploads/group-avatars",
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, file.fieldname + "-" + uniqueSuffix + path.extname(file.originalname));
  }
});
var upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "image/gif"];
    if (!allowedTypes.includes(file.mimetype)) {
      cb(new Error("Invalid file type"));
      return;
    }
    cb(null, true);
  }
});
var requireAuth2 = (req, res, next) => {
  if (!req.user?.id) {
    return res.status(401).json({ message: "Not authenticated" });
  }
  next();
};
router6.use(requireAuth2);
router6.post("/", upload.single("avatar"), async (req, res) => {
  try {
    const { name, description } = req.body;
    const avatarUrl = req.file ? `/group-avatars/${req.file.filename}` : null;
    const [newGroup] = await db.insert(groups).values({
      name,
      description,
      avatarUrl,
      createdBy: req.user.id
    }).returning();
    await db.insert(groupMembers).values({
      groupId: newGroup.id,
      userId: req.user.id,
      role: "admin"
    });
    res.status(201).json(newGroup);
  } catch (error) {
    console.error("Error creating group:", error);
    res.status(500).json({ message: "Failed to create group" });
  }
});
router6.get("/", async (req, res) => {
  try {
    const allGroups = await db.select({
      id: groups.id,
      name: groups.name,
      description: groups.description,
      avatarUrl: groups.avatarUrl,
      createdAt: groups.createdAt,
      createdBy: groups.createdBy,
      creatorUsername: users.username,
      creatorDisplayName: users.displayName
    }).from(groups).leftJoin(users, eq7(groups.createdBy, users.id)).orderBy(desc6(groups.createdAt));
    const enrichedGroups = await Promise.all(
      allGroups.map(async (group) => {
        const memberCount = await db.select({ count: sql4`count(*)::int` }).from(groupMembers).where(eq7(groupMembers.groupId, group.id));
        const isJoined = await db.select().from(groupMembers).where(and6(
          eq7(groupMembers.groupId, group.id),
          eq7(groupMembers.userId, req.user.id)
        )).limit(1);
        const userRole = isJoined.length > 0 ? isJoined[0].role : null;
        return {
          ...group,
          memberCount: memberCount[0].count,
          isJoined: isJoined.length > 0,
          userRole,
          isAdmin: userRole === "admin"
        };
      })
    );
    res.json(enrichedGroups);
  } catch (error) {
    console.error("Error fetching groups:", error);
    res.status(500).json({ message: "Failed to fetch groups" });
  }
});
router6.put("/:groupId", upload.single("avatar"), async (req, res) => {
  try {
    const { groupId } = req.params;
    const { name, description } = req.body;
    const memberInfo = await db.select().from(groupMembers).where(and6(
      eq7(groupMembers.groupId, parseInt(groupId)),
      eq7(groupMembers.userId, req.user.id),
      eq7(groupMembers.role, "admin")
    )).limit(1);
    if (memberInfo.length === 0) {
      return res.status(403).json({ message: "Not authorized to edit this group" });
    }
    const updateData = {
      name,
      description
    };
    if (req.file) {
      updateData.avatarUrl = `/group-avatars/${req.file.filename}`;
    }
    const [updatedGroup] = await db.update(groups).set(updateData).where(eq7(groups.id, parseInt(groupId))).returning();
    res.json(updatedGroup);
  } catch (error) {
    console.error("Error updating group:", error);
    res.status(500).json({ message: "Failed to update group" });
  }
});
router6.post("/:groupId/join", async (req, res) => {
  try {
    const { groupId } = req.params;
    const existingMember = await db.select().from(groupMembers).where(and6(
      eq7(groupMembers.groupId, parseInt(groupId)),
      eq7(groupMembers.userId, req.user.id)
    )).limit(1);
    if (existingMember.length > 0) {
      return res.status(400).json({ message: "Already a member of this group" });
    }
    await db.insert(groupMembers).values({
      groupId: parseInt(groupId),
      userId: req.user.id,
      role: "member"
    });
    res.status(201).json({ message: "Successfully joined group" });
  } catch (error) {
    console.error("Error joining group:", error);
    res.status(500).json({ message: "Failed to join group" });
  }
});
router6.delete("/:groupId/leave", async (req, res) => {
  try {
    const { groupId } = req.params;
    await db.delete(groupMembers).where(and6(
      eq7(groupMembers.groupId, parseInt(groupId)),
      eq7(groupMembers.userId, req.user.id)
    ));
    res.status(204).send();
  } catch (error) {
    console.error("Error leaving group:", error);
    res.status(500).json({ message: "Failed to leave group" });
  }
});
router6.get("/:groupId/messages", async (req, res) => {
  try {
    const { groupId } = req.params;
    const isMember = await db.select().from(groupMembers).where(and6(
      eq7(groupMembers.groupId, parseInt(groupId)),
      eq7(groupMembers.userId, req.user.id)
    )).limit(1);
    if (isMember.length === 0) {
      return res.status(403).json({ message: "Not a member of this group" });
    }
    const messages = await db.select({
      id: groupMessages.id,
      content: groupMessages.content,
      createdAt: groupMessages.createdAt,
      username: users.username,
      avatarUrl: users.avatarUrl
    }).from(groupMessages).innerJoin(users, eq7(groupMessages.userId, users.id)).where(eq7(groupMessages.groupId, parseInt(groupId))).orderBy(desc6(groupMessages.createdAt));
    res.json(messages);
  } catch (error) {
    console.error("Error fetching group messages:", error);
    res.status(500).json({ message: "Failed to fetch messages" });
  }
});
router6.post("/:groupId/messages", async (req, res) => {
  try {
    const { groupId } = req.params;
    const { content } = req.body;
    const isMember = await db.select().from(groupMembers).where(and6(
      eq7(groupMembers.groupId, parseInt(groupId)),
      eq7(groupMembers.userId, req.user.id)
    )).limit(1);
    if (isMember.length === 0) {
      return res.status(403).json({ message: "Not a member of this group" });
    }
    const [newMessage] = await db.insert(groupMessages).values({
      groupId: parseInt(groupId),
      userId: req.user.id,
      content
    }).returning();
    res.status(201).json(newMessage);
  } catch (error) {
    console.error("Error sending message:", error);
    res.status(500).json({ message: "Failed to send message" });
  }
});
router6.get("/:groupId/reviews", async (req, res) => {
  try {
    const { groupId } = req.params;
    const isMember = await db.select().from(groupMembers).where(and6(
      eq7(groupMembers.groupId, parseInt(groupId)),
      eq7(groupMembers.userId, req.user.id)
    )).limit(1);
    if (isMember.length === 0) {
      return res.status(403).json({ message: "Not a member of this group" });
    }
    const groupReviews = await db.select({
      id: reviews.id,
      userId: reviews.userId,
      placeId: reviews.placeId,
      placeName: reviews.placeName,
      rating: reviews.rating,
      comment: reviews.comment,
      createdAt: reviews.createdAt,
      username: users.username,
      location: reviews.location
    }).from(reviews).innerJoin(users, eq7(reviews.userId, users.id)).where(eq7(reviews.groupId, parseInt(groupId))).orderBy(desc6(reviews.createdAt));
    res.json(groupReviews);
  } catch (error) {
    console.error("Error fetching group reviews:", error);
    res.status(500).json({ message: "Failed to fetch group reviews" });
  }
});
var groups_default = router6;

// server/routes.ts
import express3 from "express";
import multer2 from "multer";
import path2 from "path";
import fs from "fs";
import { eq as eq8 } from "drizzle-orm";
var storage2 = multer2.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, "./uploads");
  },
  filename: (_req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});
var upload2 = multer2({ storage: storage2 });
function registerRoutes(app2) {
  const uploadsDir = path2.join(process.cwd(), "uploads");
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
  }
  const groupAvatarsDir = path2.join(uploadsDir, "group-avatars");
  if (!fs.existsSync(groupAvatarsDir)) {
    fs.mkdirSync(groupAvatarsDir);
  }
  app2.use("/uploads", express3.static(uploadsDir));
  app2.use("/group-avatars", express3.static(groupAvatarsDir));
  app2.use(express3.json());
  if (process.env.NODE_ENV === "production") {
    app2.use(express3.static("dist"));
    app2.get("*", (req, res) => {
      res.sendFile(path2.join(process.cwd(), "dist", "index.html"));
    });
  } else {
    app2.get("/", (req, res) => res.status(200).send("OK"));
  }
  app2.use((err, req, res, next) => {
    if (err instanceof SyntaxError && "body" in err) {
      return res.status(400).json({ error: "Invalid JSON" });
    }
    next(err);
  });
  setupAuth(app2);
  app2.put("/api/profile", upload2.single("avatar"), async (req, res) => {
    if (!req.user?.id) {
      return res.status(401).json({ error: "Not authenticated" });
    }
    try {
      const updateData = {};
      if (req.body.displayName !== void 0) updateData.displayName = req.body.displayName;
      if (req.body.bio !== void 0) updateData.bio = req.body.bio;
      if (req.body.location !== void 0) updateData.location = req.body.location;
      if (req.body.username && req.body.username !== req.user.username) {
        const existingUser = await db.query.users.findFirst({
          where: eq8(users.username, req.body.username)
        });
        if (existingUser) {
          return res.status(400).json({ error: "Username already taken" });
        }
        updateData.username = req.body.username;
      }
      if (req.file) {
        updateData.avatarUrl = `/uploads/${req.file.filename}`;
      }
      console.log("Updating profile with data:", updateData);
      await db.update(users).set(updateData).where(eq8(users.id, req.user.id));
      res.json({ message: "Profile updated successfully" });
    } catch (error) {
      console.error("Profile update error:", error);
      res.status(500).json({ error: "Failed to update profile" });
    }
  });
  app2.use("/api", router);
  app2.use("/api", router2);
  app2.use("/api/reviews", reviews_default);
  app2.use("/api/trips", tripsRouter);
  app2.use("/api", socialRouter);
  app2.use("/api/groups", groups_default);
  const httpServer = createServer(app2);
  return httpServer;
}

// server/vite.ts
import express4 from "express";
import fs2 from "fs";
import path4, { dirname as dirname2 } from "path";
import { fileURLToPath as fileURLToPath2 } from "url";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import themePlugin from "@replit/vite-plugin-shadcn-theme-json";
import path3, { dirname } from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
import { fileURLToPath } from "url";
var __filename = fileURLToPath(import.meta.url);
var __dirname = dirname(__filename);
var vite_config_default = defineConfig({
  plugins: [react(), runtimeErrorOverlay(), themePlugin()],
  resolve: {
    alias: {
      "@db": path3.resolve(__dirname, "db"),
      "@": path3.resolve(__dirname, "client", "src")
    }
  },
  root: path3.resolve(__dirname, "client"),
  build: {
    outDir: path3.resolve(__dirname, "dist/public"),
    emptyOutDir: true
  }
});

// server/vite.ts
var __filename2 = fileURLToPath2(import.meta.url);
var __dirname2 = dirname2(__filename2);
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        if (msg.includes("[TypeScript] Found 0 errors. Watching for file changes")) {
          log("no errors found", "tsc");
          return;
        }
        if (msg.includes("[TypeScript] ")) {
          const [errors, summary] = msg.split("[TypeScript] ", 2);
          log(`${summary} ${errors}\x1B[0m`, "tsc");
          return;
        } else {
          viteLogger.error(msg, options);
          process.exit(1);
        }
      }
    },
    server: {
      middlewareMode: true,
      hmr: { server }
    },
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path4.resolve(
        __dirname2,
        "..",
        "client",
        "index.html"
      );
      const template = await fs2.promises.readFile(clientTemplate, "utf-8");
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path4.resolve(__dirname2, "public");
  if (!fs2.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express4.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path4.resolve(distPath, "index.html"));
  });
}

// server/index.ts
import { sql as sql5 } from "drizzle-orm";
import cors from "cors";
var app = express5();
app.use(express5.json());
app.use(express5.urlencoded({ extended: false }));
app.use(cors({
  origin: ["https://voxa-social-app-sophiehennessy.replit.app", "http://localhost:5173"],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use((req, res, next) => {
  const start = Date.now();
  const path5 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path5.startsWith("/api")) {
      let logLine = `${req.method} ${path5} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
(async () => {
  try {
    await db.execute(sql5`SELECT 1`);
    log("Database connection successful");
    const server = registerRoutes(app);
    app.use((err, _req, res, _next) => {
      const status = err.status || err.statusCode || 500;
      const message = err.message || "Internal Server Error";
      log(`Error: ${message}`);
      res.status(status).json({ message });
    });
    if (app.get("env") === "development") {
      await setupVite(app, server);
    } else {
      serveStatic(app);
    }
    const PORT = 5e3;
    server.on("error", (error) => {
      if (error.code === "EADDRINUSE") {
        log(`Port ${PORT} is already in use. Please kill any existing processes using this port.`);
        process.exit(1);
      } else {
        throw error;
      }
    });
    server.listen(PORT, "0.0.0.0", () => {
      log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    log(`Failed to start server: ${error}`);
    process.exit(1);
  }
})();

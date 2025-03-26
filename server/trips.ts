import express from "express";
import { db } from "@db";
import { trips, tripPlaces, users } from "@db/schema";
import { eq, and, desc } from "drizzle-orm";
import OpenAI from "openai";

const router = express.Router();

// Initialize OpenAI API client if API key is available
const openai = process.env.OPENAI_API_KEY ? new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
}) : null;

// Middleware to ensure user is authenticated
function ensureAuthenticated(req: any, res: any, next: any) {
  console.log('Trips auth check:', {
    isAuthenticated: req.isAuthenticated?.(),
    userId: req.user?.id,
    session: req.session
  });

  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: "Not logged in" });
  }
  next();
}

// Get public trips - no authentication required
router.get("/public", async (req, res) => {
  try {
    console.log('Fetching public trips');
    const publicTrips = await db.query.trips.findMany({
      where: eq(trips.isPublic, true),
      orderBy: [desc(trips.createdAt)],
    });

    console.log('Found public trips:', publicTrips);

    // For each trip, count the number of places
    const tripsWithPlacesCount = await Promise.all(
      publicTrips.map(async (trip) => {
        const places = await db.query.tripPlaces.findMany({
          where: eq(tripPlaces.tripId, trip.id),
        });

        // Get the username for each trip
        const user = await db.query.users.findFirst({
          where: eq(users.id, trip.userId),
          columns: {
            username: true,
          },
        });

        console.log(`Processing trip ${trip.id}:`, {
          places: places.length,
          username: user?.username
        });

        return {
          ...trip,
          username: user?.username,
          placesCount: places.length,
        };
      })
    );

    console.log('Sending processed trips:', tripsWithPlacesCount);
    res.json(tripsWithPlacesCount);
  } catch (error) {
    console.error("Error fetching public trips:", error);
    res.status(500).json({ error: "Failed to fetch public trips" });
  }
});

// Get shared/public trip by ID - no authentication required
router.get("/shared/:id", async (req, res) => {
  try {
    console.log('Fetching shared trip:', req.params.id);
    const trip = await db.query.trips.findFirst({
      where: and(
        eq(trips.id, parseInt(req.params.id)),
        eq(trips.isPublic, true)
      ),
    });

    if (!trip) {
      return res.status(404).json({ error: "Trip not found or is private" });
    }

    // Get the username for the trip
    const user = await db.query.users.findFirst({
      where: eq(users.id, trip.userId),
      columns: {
        username: true,
      },
    });

    // Get the places for this trip
    const places = await db.query.tripPlaces.findMany({
      where: eq(tripPlaces.tripId, trip.id),
    });

    console.log('Found shared trip:', { ...trip, username: user?.username, places });

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

// Get all trips for the current user
router.get("/", ensureAuthenticated, async (req, res) => {
  try {
    console.log('Fetching trips for user:', req.user!.id);

    const userTrips = await db.query.trips.findMany({
      where: eq(trips.userId, req.user!.id),
      orderBy: [desc(trips.createdAt)],
    });

    console.log('Found trips:', userTrips);
    res.json(userTrips);
  } catch (error) {
    console.error("Error fetching trips:", error);
    res.status(500).json({ error: "Failed to fetch trips" });
  }
});

// Get a single trip by ID (for authenticated users)
router.get("/:id", ensureAuthenticated, async (req, res) => {
  try {
    const trip = await db.query.trips.findFirst({
      where: eq(trips.id, parseInt(req.params.id)),
    });

    if (!trip) {
      return res.status(404).json({ error: "Trip not found" });
    }

    if (trip.userId !== req.user!.id) {
      return res.status(403).json({ error: "Not authorized to view this trip" });
    }

    // Get the places for this trip
    const places = await db.query.tripPlaces.findMany({
      where: eq(tripPlaces.tripId, trip.id),
    });

    res.json({ ...trip, places });
  } catch (error) {
    console.error("Error fetching trip:", error);
    res.status(500).json({ error: "Failed to fetch trip" });
  }
});

// Create a new trip
router.post("/", ensureAuthenticated, async (req, res) => {
  try {
    console.log('Creating new trip for user:', req.user!.id);
    console.log('Trip data:', req.body);

    const { name, description, startDate, endDate, isPublic } = req.body;

    const [newTrip] = await db.insert(trips).values({
      userId: req.user!.id,
      name,
      description,
      startDate: startDate ? new Date(startDate) : null,
      endDate: endDate ? new Date(endDate) : null,
      isPublic: isPublic || false,
    }).returning();

    console.log('Created trip:', newTrip);
    res.json(newTrip);
  } catch (error) {
    console.error("Error creating trip:", error);
    res.status(500).json({ error: "Failed to create trip" });
  }
});

// Update trip details
router.patch("/:id", ensureAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, startDate, endDate, isPublic } = req.body;

    const trip = await db.query.trips.findFirst({
      where: eq(trips.id, parseInt(id)),
    });

    if (!trip) {
      return res.status(404).json({ error: "Trip not found" });
    }

    if (trip.userId !== req.user!.id) {
      return res.status(403).json({ error: "Not authorized to update this trip" });
    }

    const [updatedTrip] = await db
      .update(trips)
      .set({
        name: name !== undefined ? name : trip.name,
        description: description !== undefined ? description : trip.description,
        startDate: startDate !== undefined ? startDate : trip.startDate,
        endDate: endDate !== undefined ? endDate : trip.endDate,
        isPublic: isPublic !== undefined ? isPublic : trip.isPublic,
      })
      .where(eq(trips.id, parseInt(id)))
      .returning();

    res.json(updatedTrip);
  } catch (error) {
    console.error("Error updating trip:", error);
    res.status(500).json({ error: "Failed to update trip" });
  }
});

// Delete a trip
router.delete("/:id", ensureAuthenticated, async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`Attempting to delete trip ${id}`);
    
    // First verify the trip exists and belongs to the user
    const trip = await db.query.trips.findFirst({
      where: eq(trips.id, parseInt(id)),
    });

    if (!trip) {
      return res.status(404).json({ error: "Trip not found" });
    }

    if (trip.userId !== req.user!.id) {
      return res.status(403).json({ error: "Not authorized to delete this trip" });
    }
    
    // First delete all associated places
    await db.delete(tripPlaces)
      .where(eq(tripPlaces.tripId, parseInt(id)));
    
    console.log(`Deleted associated places for trip ${id}`);
    
    // Then delete the trip itself
    await db.delete(trips)
      .where(eq(trips.id, parseInt(id)));
    
    console.log(`Successfully deleted trip ${id}`);
    
    res.json({ success: true, message: "Trip deleted successfully" });
  } catch (error) {
    console.error("Error deleting trip:", error);
    res.status(500).json({ error: "Failed to delete trip" });
  }
});

// Add place to a trip
router.post("/:id/places", ensureAuthenticated, async (req, res) => {
  try {
    const tripId = parseInt(req.params.id);
    console.log(`Adding place to trip ${tripId}`);
    console.log('Request body:', req.body);
    
    // Verify the trip exists and belongs to the user
    const trip = await db.query.trips.findFirst({
      where: eq(trips.id, tripId),
    });
    
    if (!trip) {
      return res.status(404).json({ error: "Trip not found" });
    }
    
    if (trip.userId !== req.user!.id) {
      return res.status(403).json({ error: "Not authorized to update this trip" });
    }
    
    // Extract place details from request
    const { placeId, placeName, placeAddress, notes, visitDate } = req.body;
    
    if (!placeId || !placeName) {
      return res.status(400).json({ error: "Place ID and name are required" });
    }
    
    // Insert the new place into the database
    const [newPlace] = await db.insert(tripPlaces).values({
      tripId,
      placeId,
      placeName,
      placeAddress: placeAddress || null,
      notes: notes || null,
      visitDate: visitDate ? new Date(visitDate) : null,
    }).returning();
    
    console.log('Added place to trip:', newPlace);
    res.status(201).json(newPlace);
  } catch (error) {
    console.error("Error adding place to trip:", error);
    res.status(500).json({ error: "Failed to add place to trip" });
  }
});

// Get all places for a trip
router.get("/:id/places", ensureAuthenticated, async (req, res) => {
  try {
    const tripId = parseInt(req.params.id);
    console.log(`Fetching places for trip ${tripId}`);
    
    // Verify the trip exists and belongs to the user
    const trip = await db.query.trips.findFirst({
      where: eq(trips.id, tripId),
    });
    
    if (!trip) {
      return res.status(404).json({ error: "Trip not found" });
    }
    
    if (trip.userId !== req.user!.id) {
      return res.status(403).json({ error: "Not authorized to view this trip" });
    }
    
    // Get all places for this trip
    const places = await db.query.tripPlaces.findMany({
      where: eq(tripPlaces.tripId, tripId),
    });
    
    console.log(`Found ${places.length} places for trip ${tripId}`);
    res.json(places);
  } catch (error) {
    console.error("Error fetching trip places:", error);
    res.status(500).json({ error: "Failed to fetch trip places" });
  }
});

// Generate trip suggestions using OpenAI
router.post("/:id/suggestions", ensureAuthenticated, async (req, res) => {
  try {
    const tripId = parseInt(req.params.id);
    console.log(`Generating AI suggestions for trip ${tripId}`);

    // Get the trip details
    const trip = await db.query.trips.findFirst({
      where: eq(trips.id, tripId),
    });

    if (!trip) {
      return res.status(404).json({ error: "Trip not found" });
    }

    if (trip.userId !== req.user!.id) {
      return res.status(403).json({ error: "Not authorized to access this trip" });
    }

    // Get places for this trip
    const places = await db.query.tripPlaces.findMany({
      where: eq(tripPlaces.tripId, tripId),
    });

    if (places.length === 0) {
      return res.status(400).json({ error: "Trip has no places to generate suggestions for" });
    }

    console.log(`Found ${places.length} places for trip ${tripId}`);

    // Format the places data for the prompt
    const placesText = places.map(place => {
      return `- ${place.placeName}${place.placeAddress ? ` (${place.placeAddress})` : ''}${place.notes ? `. Notes: ${place.notes}` : ''}`;
    }).join("\n");

    // Create the prompt for OpenAI
    const prompt = `I'm planning a trip with the following places:
    
${placesText}

Given these locations${trip.startDate && trip.endDate ? ` and a trip duration from ${new Date(trip.startDate).toLocaleDateString()} to ${new Date(trip.endDate).toLocaleDateString()}` : ''}, please create a detailed itinerary that:

1. Groups these locations by proximity/neighborhood for efficient travel
2. Organizes them into a logical day-by-day schedule${trip.startDate && trip.endDate ? ` covering the ${Math.ceil((new Date(trip.endDate).getTime() - new Date(trip.startDate).getTime()) / (1000 * 60 * 60 * 24)) + 1} day(s) of my trip` : ''}
3. Suggests optimal times to visit each place
4. Adds travel tips and recommendations for each day
5. Suggests logical meal breaks between activities

Format the response with clear day headers (Day 1, Day 2, etc.) and time blocks (Morning, Afternoon, Evening).`;

    console.log("Sending request to OpenAI");
    
    if (!openai) {
      return res.status(503).json({ error: "OpenAI service is not available. Please configure an API key." });
    }
    
    try {
      // Make the OpenAI API call
      const completion = await openai.chat.completions.create({
        messages: [
          { 
            role: "system", 
            content: "You are a helpful travel assistant that helps plan detailed trip itineraries. Important: Do not use markdown formatting such as bold, italics, or headers in your response. Use plain text only with clear day markers like 'Day 1:' and time blocks like 'Morning:' without any formatting."
          },
          { role: "user", content: prompt }
        ],
        model: "gpt-3.5-turbo",
        temperature: 0.7,
      });
  
      // Extract and process the suggestion text
      let suggestions = completion.choices[0].message.content || '';
      
      // Remove any markdown formatting that might be present
      suggestions = suggestions.replace(/\*\*/g, ''); // Remove bold (double asterisks)
      suggestions = suggestions.replace(/\*/g, '');   // Remove italics (single asterisks)
      suggestions = suggestions.replace(/^#+ (.+)$/gm, '$1'); // Remove headers
      
      console.log("Received suggestions from OpenAI");
      res.json({ suggestions });
    } catch (error) {
      console.error("Error calling OpenAI API:", error);
      return res.status(503).json({ error: "Failed to generate suggestions with OpenAI" });
    }
  } catch (error) {
    console.error("Error generating trip suggestions:", error);
    res.status(500).json({ error: "Failed to generate trip suggestions" });
  }
});

export const tripsRouter = router;
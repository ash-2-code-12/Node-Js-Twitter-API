// imports
const express = require('express')
const path = require('path')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')


// create express instance
const app = express()
app.use(express.json())


// DATABASE preprocessing
const dbPath = path.join(__dirname, 'twitterClone.db')
let dbObj = null


// Secret key for encryption and token generation
const saltRounds = 10
const secretKey = 'encrypter_1171'


// function to connect to DB and start server
const initialiseDbAndServer = async () => {
  try {
    dbObj = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    })


    app.listen(3000, () => {
      console.log('Server running on http://localhost:3000')
    })
  } catch (e) {
    console.log(`DB error : ${e.message}`)
    process.exit(1)
  }
}


// connect DB and start server
initialiseDbAndServer()


// function to check if user already exists
const isUserPresent = async username => {
  return await dbObj.get(`SELECT * FROM user WHERE username = ?;`, [username])
}


// 1) Register User API
app.post('/register/', async (request, response) => {
  try {
    const {username, password, name, gender} = request.body


    // check username already exists
    if (await isUserPresent(username)) {
      response.status(400).send('User already exists')
      return
    }


    // check and hash password
    if (password.length < 6) {
      response.status(400).send('Password is too short')
      return
    }
    const hashedPassword = await bcrypt.hash(password, saltRounds)


    // register user
    const registerUserQuery = `INSERT INTO user (name, username, password, gender)
    VALUES(?, ?, ?, ?);`


    await dbObj.run(registerUserQuery, [name, username, hashedPassword, gender])


    response.send('User created successfully')
  } catch (e) {
    console.log(e)
    response.status(500).send('An Error occurred while Registering user')
  }
})


// 2) Login User API
app.post('/login/', async (request, response) => {
  try {
    const {username, password} = request.body


    // check user registered
    const resultUser = await isUserPresent(username)
    if (!resultUser) {
      response.status(400).send('Invalid user')
      return
    }


    // check password
    const isPasswordMatched = await bcrypt.compare(
      password,
      resultUser.password,
    )
    if (!isPasswordMatched) {
      response.status(400).send('Invalid password')
      return
    }


    // create jwt Token and send as response
    const payload = {username, userId: resultUser.user_id}
    const jwtToken = jwt.sign(payload, secretKey)


    response.send({jwtToken})
  } catch (e) {
    console.log(e)
    response.status(500).send('An Error occurred while Registering user')
  }
})


// Authenticate token Middleware
const authenticateToken = (request, response, next) => {
  let jwtToken
  const authHeader = request.headers['authorization']


  if (authHeader) {
    jwtToken = authHeader.split(' ')[1]
  }


  if (!jwtToken) {
    response.status(401).send('Invalid JWT Token')
    return
  }


  jwt.verify(jwtToken, secretKey, async (error, payload) => {
    if (error) {
      response.status(401).send('Invalid JWT Token')
      return
    }


    request.username = payload.username
    request.userId = payload.userId
    next()
  })
}


// 3) Get 4 recent Tweets of following users API
app.get('/user/tweets/feed/', authenticateToken, async (request, response) => {
  try {
    const {userId} = request


    const fetchRecentTweetsQuery = `SELECT u.username, t.tweet, t.date_time AS dateTime
    FROM tweet t
    JOIN follower f ON t.user_id = f.following_user_id
    JOIN user u ON u.user_id = t.user_id
    WHERE f.follower_user_id = ?
    ORDER BY t.date_time DESC
    LIMIT 4;`


    const tweetsList = await dbObj.all(fetchRecentTweetsQuery, [userId])


    response.send(tweetsList)
  } catch (e) {
    console.log(e)
    response.status(500).send('An Error occurred while fetching recent tweets')
  }
})


// 4) Get all names of users following the user API
app.get('/user/following/', authenticateToken, async (request, response) => {
  try {
    const {userId} = request


    const fetchFollowingUsersQuery = `SELECT name
    FROM user u
    JOIN follower f ON u.user_id = f.following_user_id
    WHERE f.follower_user_id = ?;`


    const followersList = await dbObj.all(fetchFollowingUsersQuery, [userId])


    response.send(followersList)
  } catch (e) {
    console.log(e)
    response.status(500).send('An Error occurred while getting followers names')
  }
})


// 5 ) Get followers of user API
app.get('/user/followers/', authenticateToken, async (request, response) => {
  try {
    const {userId} = request


    const fetchFollowersQuery = `SELECT name
    FROM user u
    JOIN follower f ON u.user_id = f.follower_user_id
    WHERE f.following_user_id = ?;`


    const followersList = await dbObj.all(fetchFollowersQuery, [userId])


    response.send(followersList)
  } catch (e) {
    console.log(e)
    response.status(500).send('An Error occurred while getting followers names')
  }
})


// 6) Get tweet API
app.get('/tweets/:tweetId/', authenticateToken, async (request, response) => {
  try {
    const {tweetId} = request.params
    const {userId} = request


    const fetchTweetQuery = `
    SELECT
    t.tweet,
    COUNT(DISTINCT l.like_id) AS likes,
    COUNT(DISTINCT r.reply_id) AS replies,
    t.date_time AS dateTime
    FROM tweet t
    LEFT JOIN follower f ON t.user_id = f.following_user_id
    LEFT JOIN like l ON t.tweet_id = l.tweet_id
    LEFT JOIN reply r ON t.tweet_id = r.tweet_id
    WHERE t.tweet_id = ? AND f.follower_user_id = ?
    GROUP BY t.tweet_id;`


    const resultTweet = await dbObj.get(fetchTweetQuery, [tweetId, userId])


    if (!resultTweet) {
      response.status(401).send('Invalid Request')
      return
    }


    response.send(resultTweet)
  } catch (e) {
    console.log(e)
    response.status(500).send('An Error occurred while getting tweet')
  }
})


// 7) Get likes of tweet API
app.get(
  '/tweets/:tweetId/likes/',
  authenticateToken,
  async (request, response) => {
    try {
      const {tweetId} = request.params
      const {userId} = request


      const fetchTweetLikesQuery = `
      SELECT u.username
      FROM user u
      JOIN like l ON l.user_id = u.user_id
      JOIN tweet t ON t.tweet_id = l.tweet_id
      JOIN follower f ON f.following_user_id = t.user_id
      WHERE l.tweet_id = ? AND f.follower_user_id = ?;`


      const likesUsernames = await dbObj.all(fetchTweetLikesQuery, [
        tweetId,
        userId,
      ])


      if (likesUsernames.length == 0) {
        response.status(401).send('Invalid Request')
        return
      }
      // If there are no likes but the tweet exists, still send an empty likes array
      response.send({likes: likesUsernames.map(each => each.username)})
    } catch (e) {
      console.log(e)
      response.status(500).send('An Error occurred while getting tweet likes')
    }
  },
)


// 8) Get replies of tweet
app.get(
  '/tweets/:tweetId/replies/',
  authenticateToken,
  async (request, response) => {
    try {
      const {tweetId} = request.params
      const {userId} = request


      const fetchTweetRepliesQuery = `
      SELECT u.name, r.reply
      FROM reply r
      JOIN user u ON r.user_id = u.user_id
      JOIN tweet t ON r.tweet_id = t.tweet_id
      JOIN follower f ON t.user_id = f.following_user_id
      WHERE r.tweet_id = ? AND f.follower_user_id = ?;`


      const replies = await dbObj.all(fetchTweetRepliesQuery, [tweetId, userId])


      // Check if replies list is empty
      if (replies.length === 0) {
        response.status(401).send('Invalid Request')
        return
      }


      // If there are no replies but the tweet exists, still send an empty replies array
      response.send({replies})
    } catch (e) {
      console.log(e)
      response.status(500).send('An Error occurred while getting tweet replies')
    }
  },
)


// 9) Get all user tweets API
app.get('/user/tweets/', authenticateToken, async (request, response) => {
  try {
    const {userId} = request


    const fetchUserTweetsQuery = `
    SELECT
    t.tweet,
    COUNT(DISTINCT l.like_id) AS likes,
    COUNT(DISTINCT r.reply_id) AS replies,
    t.date_time AS dateTime
    FROM tweet t
    LEFT JOIN like l ON t.tweet_id = l.tweet_id
    LEFT JOIN reply r ON t.tweet_id = r.tweet_id
    WHERE t.user_id = ?
    GROUP BY t.tweet_id;`


    const userTweets = await dbObj.all(fetchUserTweetsQuery, [userId])


    response.send(userTweets)
  } catch (e) {
    console.log(e)
    response.status(500).send('An Error occurred while getting tweet')
  }
})


const formatDateTime = date => {
  const year = date.getFullYear()
  const month = String(date.getMonth() + 1).padStart(2, '0') // Month is zero-based
  const day = String(date.getDate()).padStart(2, '0')
  const hours = String(date.getHours()).padStart(2, '0')
  const minutes = String(date.getMinutes()).padStart(2, '0')
  const seconds = String(date.getSeconds()).padStart(2, '0')
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`
}


// 10) Create a tweet API
app.post('/user/tweets/', authenticateToken, async (request, response) => {
  try {
    const {userId} = request
    const {tweet} = request.body
    const dateTime = formatDateTime(new Date())


    // check tweet length
    if (tweet.length > 280) {
      response.status(400).send('Tweet is too long')
      return
    }


    // create tweet
    const createTweetQuery = `INSERT INTO tweet (tweet, user_id, date_time)
    VALUES(?, ?, ?);`


    await dbObj.run(createTweetQuery, [tweet, userId, dateTime])


    response.send('Created a Tweet')
  } catch (e) {
    console.log(e)
    response.status(500).send('An Error occurred while creating a tweet')
  }
})


// 11) Delete a tweet API
app.delete(
  '/tweets/:tweetId/',
  authenticateToken,
  async (request, response) => {
    try {
      const {tweetId} = request.params
      const {userId} = request


      const deleteTweetQuery = `DELETE FROM tweet
    WHERE tweet_id = ? AND user_id = ?;`


      const deletedTweet = await dbObj.run(deleteTweetQuery, [tweetId, userId])


      // Check if any rows were affected
      if (deletedTweet.changes === 0) {
        response.status(401).send('Invalid Request')
        return
      }


      response.send('Tweet Removed')
    } catch (e) {
      console.log(e)
      response.status(500).send('An Error occurred while deleting tweet')
    }
  },
)


// 12) Follow a user API
app.post(
  '/user/following/:userId/',
  authenticateToken,
  async (request, response) => {
    try {
      const {userId} = request
      const {userId: userToFollow} = request.params


      const followUserQuery = `INSERT INTO follower (follower_user_id, following_user_id)
    VALUES(?, ?);`


      await dbObj.run(followUserQuery, [userId, userToFollow])


      response.send('Successfully followed')
    } catch (e) {
      console.log(e)
      response.status(500).send('An Error occurred while following user')
    }
  },
)


// 13) Unfollow a user API
app.delete(
  '/user/following/:userId/',
  authenticateToken,
  async (request, response) => {
    try {
      const {userId} = request
      const {userId: userToUnfollow} = request.params


      const unfollowUserQuery = `DELETE FROM follower
    WHERE follower_user_id = ? AND following_user_id = ?;`


      const unfollowedUser = await dbObj.run(unfollowUserQuery, [
        userId,
        userToUnfollow,
      ])


      // Check if any rows were affected
      if (unfollowedUser.changes === 0) {
        response.status(401).send('Invalid Request')
        return
      }


      response.send('Successfully Unfollowed')
    } catch (e) {
      console.log(e)
      response.status(500).send('An Error occurred while unfollowing user')
    }
  },
)


// 14) Search Users by Username
app.get('/users/search/', authenticateToken, async (request, response) => {
    try {
      const { search } = request.query;
 
      // Validate search query
      if (!search || search.trim().length === 0) {
        response.status(400).send('Search query cannot be empty');
        return;
      }
 
      // Fetch users matching the search term (case-insensitive)
      const searchUsersQuery = `
        SELECT username, name
        FROM user
        WHERE username LIKE ?;
      `;
 
      const usersList = await dbObj.all(searchUsersQuery, [`%${search}%`]);
 
      // Check if any users are found
      if (usersList.length === 0) {
        response.status(404).send('No users found');
        return;
      }
 
      response.send(usersList);
    } catch (e) {
      console.log(e);
      response.status(500).send('An Error occurred while searching users');
    }
  });
 
// 15) Remove a Follower API
app.delete('/user/followers/:followerId/', authenticateToken, async (request, response) => {
    try {
      const { userId } = request;
      const { followerId } = request.params;
 
      // SQL query to delete a follower relationship
      const removeFollowerQuery = `
        DELETE FROM follower
        WHERE follower_user_id = ? AND following_user_id = ?;
      `;
 
      const removedFollower = await dbObj.run(removeFollowerQuery, [followerId, userId]);
 
      // Check if any rows were affected
      if (removedFollower.changes === 0) {
        response.status(401).send('Invalid Request');
        return;
      }
 
      response.send('Successfully removed follower');
    } catch (e) {
      console.log(e);
      response.status(500).send('An Error occurred while removing follower');
    }
  });
 
// 16) Send Follow Request API
app.post('/user/follow-request/:receiverUserId/', authenticateToken, async (request, response) => {
  try {
    const { userId: senderUserId } = request; // sender is the authenticated user
    const { receiverUserId } = request.params; // receiver is the user to be followed
    const requestDate = formatDateTime(new Date());


    // Check if follow request already exists or the user is already following
    const checkExistingRequestQuery = `
      SELECT * FROM follow_request
      WHERE sender_user_id = ? AND receiver_user_id = ? AND request_status = 'pending';`;
     
    const existingRequest = await dbObj.get(checkExistingRequestQuery, [senderUserId, receiverUserId]);


    if (existingRequest) {
      response.status(400).send('Follow request already sent and pending');
      return;
    }


    // Check if user is already following
    const checkFollowingQuery = `
      SELECT * FROM follower
      WHERE follower_user_id = ? AND following_user_id = ?;`;


    const existingFollowing = await dbObj.get(checkFollowingQuery, [senderUserId, receiverUserId]);


    if (existingFollowing) {
      response.status(400).send('Already following the user');
      return;
    }


    // Insert a new follow request
    const createFollowRequestQuery = `
      INSERT INTO follow_request (sender_user_id, receiver_user_id, request_status, request_date)
      VALUES (?, ?, 'pending', ?);`;


    await dbObj.run(createFollowRequestQuery, [senderUserId, receiverUserId, requestDate]);


    response.send('Follow request sent');
  } catch (e) {
    console.log(e);
    response.status(500).send('An Error occurred while sending follow request');
  }
});


// 17) Accept Follow Request API
app.post('/user/follow-request/:requestId/accept', authenticateToken, async (request, response) => {
    try {
      const { userId: receiverUserId } = request; // the authenticated user is the receiver
      const { requestId } = request.params;
 
      // Check if the follow request exists and is pending for the authenticated user
      const fetchFollowRequestQuery = `
        SELECT * FROM follow_request
        WHERE request_id = ? AND receiver_user_id = ? AND request_status = 'pending';`;
 
      const followRequest = await dbObj.get(fetchFollowRequestQuery, [requestId, receiverUserId]);
 
      if (!followRequest) {
        response.status(400).send('Invalid follow request');
        return;
      }
 
      // Add to the followers table
      const addFollowerQuery = `
        INSERT INTO follower (follower_user_id, following_user_id)
        VALUES (?, ?);`;
 
      await dbObj.run(addFollowerQuery, [followRequest.sender_user_id, followRequest.receiver_user_id]);
 
      // Update follow request status to 'accepted'
      const updateFollowRequestQuery = `
        UPDATE follow_request
        SET request_status = 'accepted'
        WHERE request_id = ?;`;
 
      await dbObj.run(updateFollowRequestQuery, [requestId]);
 
      response.send('Follow request accepted');
    } catch (e) {
      console.log(e);
      response.status(500).send('An error occurred while accepting the follow request');
    }
  });
 
// 18) Reject Follow Request API
app.post('/user/follow-request/:requestId/reject', authenticateToken, async (request, response) => {
    try {
      const { userId: receiverUserId } = request; // the authenticated user is the receiver
      const { requestId } = request.params;
 
      // Check if the follow request exists and is pending for the authenticated user
      const fetchFollowRequestQuery = `
        SELECT * FROM follow_request
        WHERE request_id = ? AND receiver_user_id = ? AND request_status = 'pending';`;
 
      const followRequest = await dbObj.get(fetchFollowRequestQuery, [requestId, receiverUserId]);
 
      if (!followRequest) {
        response.status(400).send('Invalid follow request');
        return;
      }
 
      // Update follow request status to 'rejected'
      const updateFollowRequestQuery = `
        UPDATE follow_request
        SET request_status = 'rejected'
        WHERE request_id = ?;`;
 
      await dbObj.run(updateFollowRequestQuery, [requestId]);
 
      response.send('Follow request rejected');
    } catch (e) {
      console.log(e);
      response.status(500).send('An error occurred while rejecting the follow request');
    }
  });
 
module.exports = app

package repositories

import javax.inject.Singleton
import models.{Comment, Post}

@Singleton
class DataRepository {

  private val posts = Seq(
    Post(1, "Breaking: New AI Breakthrough Changes Everything"),
    Post(2, "Latest: SpaceX Successfully Lands on Mars")
  )

  private val comments = Seq(
    Comment(1, 1, "This AI development is mind-blowing!", "Tech Enthusiast"),
    Comment(2, 1, "Can't wait to see what's next in AI", "Future Watcher"),
    Comment(3, 2, "Historic moment for space exploration", "Space Fan")
  )

  def getPost(postId: Int): Option[Post] = posts.collectFirst {
    case p if p.id == postId => p
  }

  def getPosts: Seq[Post] = posts

  def getComments(postId: Int): Seq[Comment] = comments.collect {
    case c if c.postId == postId => c
  }
}

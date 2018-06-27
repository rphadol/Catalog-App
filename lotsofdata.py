from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import datetime

from database_setup import Category, Base, Items, User

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Vira ", email="angel@udacity.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(User1)
session.commit()


Category1 = Category(name="Hockey",
                      user_id=1)
session.add(Category1)
session.commit()

Category2 = Category(name="Snowboarding",
                      user_id=1)
session.add(Category2)
session.commit

Category3 = Category(name="Rock Climbing",
                      user_id=1)
session.add(Category3)
session.commit()

Category4 = Category(name="Skating",
                      user_id=1)
session.add(Category4)
session.commit()

Category5 = Category(name="Football",
                      user_id=1)
session.add(Category5)
session.commit()


Item1 = Items(name="Stick",
               date=datetime.datetime.now(),
               description="Built for the advanced player with 70% carbon construction.",
               category_id=1,
               user_id=1)
session.add(Item1)
session.commit()

Item2 = Items(name="Hockey Field Ball",
               date=datetime.datetime.now(),
               description="Official size and weight. Solid white color ball.",
               category_id=1,
               user_id=1)
session.add(Item2)
session.commit()

Item3 = Items(name="Hockey Socks",
               date=datetime.datetime.now(),
               description="socks are made of Cotton/Polyester blend,elasticized ankle to fit any ankle machine washable ",
               category_id=1,
               user_id=1)
session.add(Item3)
session.commit()



print "added menu items!"

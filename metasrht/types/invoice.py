import sqlalchemy as sa
from srht.database import Base

class Invoice(Base):
    __tablename__ = 'invoice'
    id = sa.Column(sa.Integer, primary_key=True)
    created = sa.Column(sa.DateTime, nullable=False)
    updated = sa.Column(sa.DateTime, nullable=False)
    cents = sa.Column(sa.Integer, nullable=False)
    user_id = sa.Column(sa.Integer, sa.ForeignKey('user.id'), nullable=False)
    user = sa.orm.relationship("User", backref="invoices")
    valid_thru = sa.Column(sa.DateTime, nullable=False)
    source = sa.Column(sa.String(256), nullable=False)

    def __repr__(self):
        return '<Invoice {} uid:{} ${:.2f}>'.format(
                self.id, self.user_id, self.cents / 100)

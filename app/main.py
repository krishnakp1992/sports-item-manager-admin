import uvicorn
import os
from datetime import timedelta
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi_sqlalchemy import DBSessionMiddleware, db

from sgor_core.schemas.admin_schema import CreateSportsGear as SchemaCreateSportsGear, CreateUser as SchemaCreateAdmin, ListUser as SchemaListUser, \
UpdateSportsGear as SchemaUpdateSportsGear, ListSportsGear as SchemaListSportsGear
from sgor_core.schemas.auth_schema import Token
from sgor_core.models import SportsGear, User

from sgor_core.utils import check_if_user_exists
from sgor_core.auth import get_password_hash, authenticate_user, ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, get_current_active_admin
from typing import List, Annotated

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm


app = FastAPI(title="Sports Gear Renting Admin")

# to avoid csrftokenError
app.add_middleware(DBSessionMiddleware, db_url=os.environ['DATABASE_URL'])




# @app.get('/book/')
# async def book():
#     book = db.session.query(ModelBook).all()
#     return book

@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends()
):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

  
@app.post('/admins/create', response_model=SchemaListUser)
async def create_admin(user:SchemaCreateAdmin):
    if check_if_user_exists(user.email):
        raise HTTPException(status_code=400, detail="User with this email already exist")
    pwd_hash = get_password_hash(user.password)
    db_user = User(name=user.name, email=user.email, phone_number=user.phone_number, address=user.address, password=pwd_hash, is_admin=True)
    db.session.add(db_user)
    db.session.commit()
    return db_user

@app.get('/admins', response_model=List[SchemaListUser])
async def admins(
    current_user: User = Depends(get_current_active_admin)
):
    author = db.session.query(User).filter_by(is_admin=True).all()
    return author


@app.post('/sportsgear/create', response_model=SchemaListSportsGear)
async def create_sports_gear(sports_gear: SchemaCreateSportsGear, current_user: User = Depends(get_current_active_admin)):
    db_sports_gear = SportsGear(name=sports_gear.name, sport=sports_gear.sport, available_count = sports_gear.available_count, user_id=current_user.id)
    db.session.add(db_sports_gear)
    db.session.commit()
    return db_sports_gear


@app.get('/sportsgears', response_model=List[SchemaListSportsGear])
async def sports_gears(
    current_user: User = Depends(get_current_active_admin)
):
    author = db.session.query(SportsGear).all()
    return author


@app.patch('/sportsgear/{sports_gear_id}/update', response_model=SchemaListSportsGear)
async def update_sports_gear(
    sports_gear_id: int, sports_gear: SchemaUpdateSportsGear, current_user: User = Depends(get_current_active_admin)
):
    sports_gear_obj = db.session.query(SportsGear).get(sports_gear_id)
    if not sports_gear:
        raise HTTPException(status_code=404, detail="Sports gear not found")
    sports_gear_data = sports_gear.dict(exclude_unset=True)
    for key, value in sports_gear_data.items():
        setattr(sports_gear_obj, key, value)
    db.session.add(sports_gear_obj)
    db.session.commit()
    db.session.refresh(sports_gear_obj)
    return sports_gear_obj

@app.delete('/sportsgear/{sports_gear_id}/delete')
async def delete_sports_gear(
    sports_gear_id: int, current_user: User = Depends(get_current_active_admin)
):
    sports_gear_obj = db.session.query(SportsGear).get(sports_gear_id)
    if sports_gear_obj:
        db.session.delete(sports_gear_obj)
        db.session.commit()
    return {'status': 'success'}

# # To run locally
# if __name__ == '__main__':
#     uvicorn.run(app, host='0.0.0.0', port=8000)
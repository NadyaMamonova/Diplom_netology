import pytest
from unittest.mock import patch, MagicMock
from myproject.myapp.views import RegisterAccount, ConfirmAccount
from django.core.exceptions import ValidationError
from myproject.myapp.models import ConfirmEmailToken
from rest_framework.test import APIRequestFactory, force_authenticate
from myproject.myapp.views import LoginAccount
from django.contrib.auth.models import User
from myproject.myapp.models import Category, Shop, ProductInfo, ProductParameter, Product
from rest_framework.test import APIClient



@pytest.mark.django_db
def test_register_account_success(api_request_factory, mock_user_serializer):
    """Тест успешной регистрации."""
    mock_serializer = MagicMock()
    mock_serializer.is_valid.return_value = True
    mock_serializer.save.return_value = User.objects.create_user(username='testuser', password='password', email='test@example.com')  #Создаем тестового пользователя

    with patch('myproject.myapp.views.UserSerializer', return_value=mock_serializer):  #патчим UserSerializer
        with patch('myproject.myapp.views.validate_password') as mock_validate_password: #патчим validate_password
            mock_validate_password.return_value = None #убираем исключение
            data = {
                'first_name': 'Test',
                'last_name': 'User',
                'email': 'testuser@example.com',
                'password': 'StrongPassword123!',
                'company': 'TestCompany',
                'position': 'Tester',
            }
            request = api_request_factory.post('/', data=data)
            view = RegisterAccount.as_view()
            response = view(request)
            assert response.status_code == 200
            assert response.json()['Status'] is True



@pytest.mark.django_db
def test_register_account_missing_fields(api_request_factory):
    """Тест регистрации с отсутствующими полями."""
    data = {
        'first_name': 'Test',
        'last_name': 'User',
        'email': 'testuser@example.com',
        'password': 'StrongPassword123!',
        'company': 'TestCompany',
    }
    request = api_request_factory.post('/', data=data)
    view = RegisterAccount.as_view()
    response = view(request)
    assert response.status_code == 200
    assert response.json()['Status'] is False
    assert response.json()['Errors'] == 'Не указаны все необходимые аргументы'


@pytest.mark.django_db
def test_register_account_weak_password(api_request_factory):
    """Тест регистрации со слабым паролем."""
    with patch('myproject.myapp.views.validate_password') as mock_validate_password:
        mock_validate_password.side_effect = ValidationError(['Password too short', 'Password too simple'])
        data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'testuser@example.com',
            'password': 'short',
            'company': 'TestCompany',
            'position': 'Tester',
        }
        request = api_request_factory.post('/', data=data)
        view = RegisterAccount.as_view()
        response = view(request)
        assert response.status_code == 200
        assert response.json()['Status'] is False
        assert 'Password too short' in response.json()['Errors']['password']
        assert 'Password too simple' in response.json()['Errors']['password']



@pytest.mark.django_db
def test_register_account_duplicate_email(api_request_factory):
    """Тест регистрации с дублирующимся email."""
    User.objects.create_user(username='testuser', email='testuser@example.com', password='password')

    with patch('myproject.myapp.views.validate_password') as mock_validate_password:
        mock_validate_password.return_value = None

        data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'testuser@example.com',
            'password': 'StrongPassword123!',
            'company': 'TestCompany',
            'position': 'Tester',
        }
        request = api_request_factory.post('/', data=data)
        view = RegisterAccount.as_view()
        response = view(request)

        #Проверка на неудачу - ожидаем ошибку сериализации из-за дубликата email
        assert response.status_code == 200
        assert response.json()['Status'] is False
        assert 'email' in response.json()['Errors'] #Проверяем что ошибка связана с email


@pytest.mark.django_db
def test_confirm_account_success(api_request_factory, create_confirm_email_token): #fixture описан ниже
    """Тест успешного подтверждения аккаунта."""
    token = create_confirm_email_token
    data = {'email': token.user.email, 'token': token.key}
    request = api_request_factory.post('/', data=data)
    view = ConfirmAccount.as_view()
    response = view(request)
    assert response.status_code == 200
    assert response.json()['Status'] is True
    assert ConfirmEmailToken.objects.filter(key=token.key).count() == 0 #Проверяем что токен удален


@pytest.mark.django_db
def test_confirm_account_invalid_token(api_request_factory):
    """Тест подтверждения аккаунта с неверным токеном."""
    data = {'email': 'test@example.com', 'token': 'invalid_token'}
    request = api_request_factory.post('/', data=data)
    view = ConfirmAccount.as_view()
    response = view(request)
    assert response.status_code == 200
    assert response.json()['Status'] is False
    assert response.json()['Errors'] == 'Неправильно указан токен или email'


@pytest.mark.django_db
def test_confirm_account_missing_fields(api_request_factory):
    """Тест подтверждения аккаунта с отсутствующими полями."""
    data = {'email': 'test@example.com'}
    request = api_request_factory.post('/', data=data)
    view = ConfirmAccount.as_view()
    response = view(request)
    assert response.status_code == 200
    assert response.json()['Status'] is False
    assert response.json()['Errors'] == 'Не указаны все необходимые аргументы'



@pytest.mark.django_db
def test_account_details_success(api_client, create_user): #fixture описан ниже
    """Тест получения данных аккаунта."""
    user = create_user
    client = APIClient()
    force_authenticate(client, user=user)
    response = client.get('user/register')
    assert response.status_code == 200
    assert response.data['email'] == user.email


@pytest.mark.django_db
def test_account_details_unauthenticated(api_client):
    """Тест получения данных аккаунта без авторизации."""
    response = api_client.get('partner/orders') # Замените на ваш url
    assert response.status_code == 403
    assert response.json()['Error'] == 'Log in required'


@pytest.mark.django_db
def test_account_details_update_password(api_client, create_user, mock_validate_password): #fixture описан ниже
    """Тест обновления пароля аккаунта."""
    user = create_user
    client = APIClient()
    force_authenticate(client, user=user)
    mock_validate_password.return_value = None
    data = {'password': 'NewStrongPassword123!'}
    response = client.post('user/password_reset', data=data)
    assert response.status_code == 200
    assert response.json()['Status'] is True


@pytest.mark.django_db
def test_account_details_update_other_data(api_client, create_user):
    user = create_user
    client = APIClient()
    force_authenticate(client, user=user)
    data = {'first_name': 'UpdatedName'}
    response = client.post('user/password_reset/confirm', data=data)
    assert response.status_code == 200
    assert response.json()['Status'] is True
    user.refresh_from_db()
    assert user.first_name == 'UpdatedName'



@pytest.fixture
def api_request_factory():
    return APIRequestFactory()

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def create_user():
    user = User.objects.create_user(username='testuser', email='testuser@example.com', password='password')
    return user


# @pytest.fixture
# def create_confirm_email_token(create_user):
#     token = ConfirmEmailToken.objects.create(user=create_user, key='valid_token')
#     return token


@pytest.fixture
def mock_validate_password():
    with patch('myproject.myapp.views.validate_password') as mock:
        yield mock


@pytest.fixture
def api_request_factory():
    return APIRequestFactory()

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def create_user():
    user = User.objects.create_user(username='testuser', email='testuser@example.com', password='password')
    return user

@pytest.fixture
def create_category():
    category = Category.objects.create(name='Test Category')
    return category

@pytest.fixture
def create_shop(create_category):
    shop = Shop.objects.create(name='Test Shop', state=True)
    return shop

@pytest.fixture
def create_product(create_category):
    product = Product.objects.create(name="test_product", category=create_category)
    return product


@pytest.fixture
def create_product_info(create_shop, create_product):
    product_info = ProductInfo.objects.create(shop=create_shop, product=create_product, price=100, quantity=10)
    return product_info

@pytest.fixture
def create_product_parameter(create_product_info):
  parameter = ProductParameter.objects.create(product_info=create_product_info, parameter=1, value='value')
  return parameter


# Tests for LoginAccount
@pytest.mark.django_db
def test_login_account_success(api_request_factory, create_user):
    data = {'email': 'testuser@example.com', 'password': 'password'}
    request = api_request_factory.post('/', data=data)
    view = LoginAccount.as_view()
    response = view(request)
    assert response.status_code == 200
    assert response.json()['Status'] is True
    assert 'Token' in response.json()


@pytest.mark.django_db
def test_login_account_wrong_password(api_request_factory, create_user):
    data = {'email': 'testuser@example.com', 'password': 'wrong_password'}
    request = api_request_factory.post('/', data=data)
    view = LoginAccount.as_view()
    response = view(request)
    assert response.status_code == 200
    assert response.json()['Status'] is False
    assert response.json()['Errors'] == 'Не удалось авторизовать'


@pytest.mark.django_db
def test_login_account_missing_fields(api_request_factory, create_user):
    data = {'email': 'testuser@example.com'}
    request = api_request_factory.post('/', data=data)
    view = LoginAccount.as_view()
    response = view(request)
    assert response.status_code == 200
    assert response.json()['Status'] is False
    assert response.json()['Errors'] == 'Не указаны все необходимые аргументы'


# Tests for CategoryView
@pytest.mark.django_db
def test_category_view(api_client, create_category):
    response = api_client.get('categories')
    assert response.status_code == 200
    assert len(response.data) >= 1 #Проверяем что хотя бы одна категория


# Tests for ShopView
@pytest.mark.django_db
def test_shop_view(api_client, create_shop):
    response = api_client.get('shops')
    assert response.status_code == 200
    assert len(response.data) >= 1 #Проверяем что хотя бы один магазин


# Tests for ProductInfoView

@pytest.mark.django_db
def test_product_info_view_all(api_client, create_product_info):
    response = api_client.get('products')
    assert response.status_code == 200
    assert len(response.data) >= 1

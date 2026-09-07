from . import app

if __name__ == '__main__':
    app.socketio.run(app, host='0.0.0.0', port=int(__import__('os').environ.get('PORT', '5000')))

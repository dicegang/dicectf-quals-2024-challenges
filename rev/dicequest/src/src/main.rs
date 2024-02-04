mod animated_sprite;
mod combat;
mod dragon;
mod generated_coords;
mod money;
mod regen;

use bevy::prelude::*;
use bevy::time::common_conditions::on_timer;

use bevy_prng::ChaCha8Rng;
use bevy_rand::prelude::*;
use rand_core::RngCore;

use animated_sprite::AnimatedSpriteBundle;
use bevy::app::AppExit;
use bevy::input::mouse::MouseWheel;
use bevy::sprite::Anchor;
use bevy::utils::HashSet;
use money::{Coins, KillReward, ShopItem};
use std::time::Duration;

#[cfg(feature = "inspect")]
use bevy_inspector_egui::{prelude::*, quick::WorldInspectorPlugin};

const PLAYER_SPEED: f32 = 500.0;
const PLAYER_SIZE: Vec2 = Vec2::new(128., 128.);
const DICE_ENEMY_SIZE: Vec2 = Vec2::new(64., 64.);
const PLAYER_REGEN_AMOUNT: f32 = 1.0;
const PLAYER_REGEN_TIMER_INITIAL: f32 = 1.0;
const PLAYER_HEALTH_INITIAL: f32 = 100.0;
const ENEMY_HEALTH_MAX: f32 = 20.0;
const PLAYER_DAMAGE_INITIAL: Damage = Damage(25.0);
const DICE_ENEMY_DAMAGE: Damage = Damage(5.0);
const PLAYER_ATTACK_COOLDOWN: Cooldown = Cooldown(2.0);
const ENEMY_ATTACK_COOLDOWN: Cooldown = Cooldown(0.1);

#[derive(Component)]
struct Player;

#[derive(Component)]
struct Enemy;

#[derive(Component)]
struct Health {
    current: f32,
    max: f32,
}

impl Health {
    pub fn new(max: f32) -> Self {
        Self { current: max, max }
    }
}

#[derive(Component)]
struct HealthBar {
    bar: Option<Entity>,
}

/// Indicate that an [`Entity`] has died and needs to be despawned.
/// Prevents a race condition with [`combat::process_attacks`] despawning the same
/// entity multiple times.
///
/// The entity should be immediately hidden and no longer do anything, but use the integer
/// to count down before despawning it, in case there are events remaining
/// (e.g. [`money::update_money`]).
#[derive(Component)]
pub struct JustDied(Option<u8>);

impl JustDied {
    pub fn new() -> Self {
        Self(None)
    }
}

#[derive(Bundle)]
struct PlayerBundle {
    health: Health,
    bar: HealthBar,
    marker: Player,
    sprite: AnimatedSpriteBundle,
    regen: regen::RegenCooldown,
    money: Coins,
    damage: Damage,
    attack_cooldown: Cooldown,
    items: OwnedItems,
    #[cfg(feature = "inspect")]
    _name: Name,
}

#[derive(Bundle)]
struct EnemyBundle {
    health: Health,
    marker: Enemy,
    sprite: SpriteBundle,
    damage: Damage,
    attack_cooldown: Cooldown,
    #[cfg(feature = "inspect")]
    _name: Name,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Default, States)]
enum GameState {
    #[default]
    Running,
    GameOver,
}

#[derive(Component)]
struct Dice;

#[derive(Event)]
struct Death {
    /// Killer, if any
    source: Option<Entity>,
    /// Killed entity
    target: Entity,
}

#[derive(Component, Default)]
struct OwnedItems(HashSet<ShopItem>);

#[derive(Component)]
/// Amount of damage per attack
struct Damage(f32);

/// Cooldown in seconds between attacks
#[derive(Component)]
#[cfg_attr(feature = "inspect", derive(Reflect, InspectorOptions))]
#[cfg_attr(feature = "inspect", reflect(Component, InspectorOptions))]
struct Cooldown(f32);

impl Default for Cooldown {
    fn default() -> Self {
        PLAYER_ATTACK_COOLDOWN
    }
}

fn main() {
    let mut app = App::new();
    let default = {
        let mut plugins = DefaultPlugins.build();
        plugins = plugins.set(ImagePlugin::default_nearest());
        #[cfg(not(debug_assertions))]
        {
            plugins = plugins.disable::<bevy::log::LogPlugin>()
        }
        plugins
    };
    app.insert_resource(ClearColor(Color::hex("#0e4217").unwrap()))
        .add_plugins(default)
        .add_plugins(EntropyPlugin::<ChaCha8Rng>::default())
        .add_plugins(regen::RegenPlugin)
        .add_plugins(combat::CombatPlugin)
        .add_plugins(animated_sprite::AnimatedSpritePlugin)
        .add_plugins(money::MoneyPlugin)
        .add_plugins(dragon::DragonPlugin)
        .add_systems(Startup, spawn_player)
        // Update
        .add_systems(
            Update,
            (
                (
                    // If running
                    (
                        move_player,
                        spawn_dice_enemy.run_if(on_timer(Duration::from_secs(2))),
                        #[cfg(debug_assertions)]
                        bevy::window::close_on_esc,
                        update_health_bar,
                    ),
                )
                    .run_if(in_state(GameState::Running)),
                // If over
                (game_over,).run_if(in_state(GameState::GameOver)),
                zoom_camera,
            ),
        )
        // Handle any deaths from the frame just past
        .add_systems(PostUpdate, process_deaths)
        .add_state::<GameState>()
        .add_event::<Death>();
    #[cfg(feature = "inspect")]
    {
        app.add_plugins(WorldInspectorPlugin::new());
        app.register_type::<Coins>();
        app.register_type::<Cooldown>();
    }
    app.run();
}

/// Spawn the [`PlayerBundle`] and attach the camera
fn spawn_player(
    mut commands: Commands,
    asset_server: Res<AssetServer>,
    mut texture_atlases: ResMut<Assets<TextureAtlas>>,
) {
    commands
        .spawn(PlayerBundle {
            health: Health::new(PLAYER_HEALTH_INITIAL),
            bar: HealthBar { bar: None },
            sprite: AnimatedSpriteBundle::new(
                asset_server.load("wiggle.png"),
                Vec2::new(128.0, 128.0),
                3,
                1,
                texture_atlases.as_mut(),
            ),
            regen: regen::RegenCooldown(Timer::from_seconds(
                PLAYER_REGEN_TIMER_INITIAL,
                TimerMode::Repeating,
            )),
            marker: Player,
            money: Coins(0),
            damage: PLAYER_DAMAGE_INITIAL,
            attack_cooldown: PLAYER_ATTACK_COOLDOWN,
            items: OwnedItems::default(),
            #[cfg(feature = "inspect")]
            _name: Name::new("Player"),
        })
        .with_children(|player| {
            player.spawn(Camera2dBundle::default());
        });
}

fn move_player(
    keyboard: Res<Input<KeyCode>>,
    mut query: Query<&mut Transform, With<Player>>,
    time: Res<Time>,
) {
    let mut player_trans = query.single_mut();
    let mut direction = Vec3::default();
    if keyboard.pressed(KeyCode::A) {
        direction.x -= 1.0;
    }
    if keyboard.pressed(KeyCode::D) {
        direction.x += 1.0;
    }
    if keyboard.pressed(KeyCode::W) {
        direction.y += 1.0;
    }
    if keyboard.pressed(KeyCode::S) {
        direction.y -= 1.0;
    }
    player_trans.translation += direction * PLAYER_SPEED * time.delta_seconds();
}

fn zoom_camera(
    mut scroll: EventReader<MouseWheel>,
    mut camera: Query<&mut OrthographicProjection, With<Camera>>,
) {
    if scroll.is_empty() {
        return;
    }
    let mut camera = camera.single_mut();
    for ev in scroll.read() {
        camera.scale = f32::max(0.5, camera.scale - ev.y / 2.0);
    }
}

fn spawn_dice_enemy(
    mut commands: Commands,
    asset_server: Res<AssetServer>,
    windows: Query<&Window>,
    rng: ResMut<GlobalEntropy<ChaCha8Rng>>,
    player: Query<&Transform, With<Player>>,
) {
    let transform = Transform::from_translation(random_position_on_screen(
        rng,
        windows.single(),
        player.single().translation,
    ));
    commands.spawn((
        EnemyBundle {
            health: Health::new(ENEMY_HEALTH_MAX),
            marker: Enemy,
            sprite: SpriteBundle {
                texture: asset_server.load("dice.png"),
                transform,
                sprite: Sprite {
                    custom_size: Some(DICE_ENEMY_SIZE),
                    ..default()
                },
                ..default()
            },
            damage: DICE_ENEMY_DAMAGE,
            attack_cooldown: ENEMY_ATTACK_COOLDOWN,
            #[cfg(feature = "inspect")]
            _name: Name::new("Dice"),
        },
        Dice,
        KillReward(5),
    ));
}

fn random_position_on_screen(
    mut rng: ResMut<GlobalEntropy<ChaCha8Rng>>,
    window: &Window,
    player_pos: Vec3,
) -> Vec3 {
    let x = (rng.next_u32() as f32 % window.resolution.width()) - window.resolution.width() / 2.0;
    let y = (rng.next_u32() as f32 % window.resolution.height()) - window.resolution.height() / 2.0;
    Vec3::new(x, y, 0.0) + player_pos
}

fn update_health_bar(
    mut commands: Commands,
    mut health: Query<(Entity, &Health, &mut HealthBar)>,
    mut bar_sprites: Query<&mut Sprite>,
) {
    const BAR_HEIGHT: f32 = 15.0;
    const BAR_WIDTH: f32 = 100.0;
    for (parent_entity, health, mut bar) in health.iter_mut() {
        let current_width = (health.current / health.max) * BAR_WIDTH;
        if let Some(front) = bar.bar {
            let mut sprite = bar_sprites.get_mut(front).unwrap();
            sprite.rect.as_mut().unwrap().max.x = current_width;
        } else {
            let transform = Transform::from_translation(Vec3::new(-50.0, -80.0, 0.0));
            let sprite_back = SpriteBundle {
                sprite: Sprite {
                    // Dark red
                    color: Color::rgb(0.1, 0.0, 0.0),
                    rect: Some(Rect {
                        min: Vec2::ZERO,
                        max: Vec2::new(BAR_WIDTH, BAR_HEIGHT),
                    }),
                    anchor: Anchor::CenterLeft,
                    ..Default::default()
                },
                transform,
                ..Default::default()
            };
            let transform = Transform::from_translation(Vec3::new(-50.0, -80.0, 0.1));
            let sprite_front = SpriteBundle {
                sprite: Sprite {
                    // Bright red
                    color: Color::rgb(0.9, 0.0, 0.0),
                    rect: Some(Rect {
                        min: Vec2::ZERO,
                        max: Vec2::new(BAR_WIDTH, BAR_HEIGHT),
                    }),
                    anchor: Anchor::CenterLeft,
                    ..Default::default()
                },
                transform: transform.with_scale(Vec3::new(current_width / 100.0, 1.0, 0.0)),
                ..Default::default()
            };
            commands.spawn(sprite_back).set_parent(parent_entity);
            let front = commands.spawn(sprite_front).set_parent(parent_entity).id();
            bar.bar = Some(front)
        }
    }
}

/// Reap any deaths from [`combat::process_attacks`]
fn process_deaths(mut commands: Commands, mut query: Query<(Entity, &mut JustDied)>) {
    for (dead, mut counter) in query.iter_mut() {
        match &mut counter.0 {
            None => {
                counter.0 = {
                    // Died this frame, hide this
                    commands.entity(dead).remove::<(Sprite, Transform)>();
                    Some(3)
                }
            }
            Some(val @ 1..) => *val -= 1,
            Some(0) => commands.entity(dead).despawn_recursive(),
        }
    }
}

fn game_over(mut exit: EventWriter<AppExit>) {
    println!("game over :(");
    exit.send(AppExit);
}
